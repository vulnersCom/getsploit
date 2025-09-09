import pathlib
import re
import sqlite3
import tempfile
import urllib.parse
import zipfile
from functools import cached_property
from typing import Any, Iterable, Mapping

import click
import httpx
import orjson
import texttable  # type:ignore[import-untyped]


class Context:
    def __init__(self, api_key: str | None = None) -> None:
        self.cli_api_key = api_key

    @cached_property
    def home_path(self) -> pathlib.Path:
        home = pathlib.Path.home() / ".getsploit"
        home.mkdir(parents=True, exist_ok=True)
        return home

    @cached_property
    def database_path(self) -> pathlib.Path:
        return self.home_path / "getsploit.db"

    @cached_property
    def api_key_path(self) -> pathlib.Path:
        return self.home_path / "vulners.key"

    @cached_property
    def client(self) -> httpx.Client:
        api_key = self.cli_api_key
        if not api_key and self.api_key_path.exists():
            api_key = self.api_key_path.read_text()
        if not api_key:
            raise click.ClickException("Vulners API key not found.")
        return httpx.Client(base_url="https://vulners.com/api/", headers={"x-api-key": api_key})


def download_database(ctx: Context) -> None:
    click.echo("Downloading getsploit database archive. Please wait...")
    with tempfile.TemporaryDirectory() as tmpdir:
        path = pathlib.Path(tmpdir) / "getsploit.db.zip"
        with (
            ctx.client.stream("GET", "v3/archive/getsploit", follow_redirects=True) as resp,
        ):
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise click.ClickException(str(e))
            with (
                click.progressbar(
                    length=int(resp.headers["Content-Length"]), label="Reading archive"
                ) as bar,
                path.open("wb") as output,
            ):
                for chunk in resp.iter_bytes():
                    output.write(chunk)
                    bar.update(len(chunk))
            with zipfile.ZipFile(path, "r") as archive:
                archive.extractall(ctx.home_path)


def search_exploit_local(ctx: Context, query: str, limit: int) -> Iterable[Mapping[str, Any]]:
    if not ctx.database_path.exists():
        raise click.ClickException("There is no local database file. Run 'getsploit --update'")
    conn = sqlite3.connect(ctx.database_path)
    cursor = conn.cursor()
    search_results = cursor.execute(
        f"SELECT * FROM exploits WHERE exploits MATCH ? ORDER BY published LIMIT ?",
        (query, limit),
    ).fetchall()
    fields = [d[0] for d in cursor.description]
    for row in search_results:
        yield dict(zip(fields, row))


def search_exploit_online(ctx: Context, query: str, limit: int) -> Iterable[Mapping[str, Any]]:
    resp = ctx.client.post(
        "v3/search/lucene/",
        json={
            "query": f"bulletinFamily:exploit AND ({query})",
            "size": limit,
            "fields": ["id", "type", "title", "description", "sourceData", "published"],
        },
    )
    resp.raise_for_status()
    data = resp.json()["data"]
    if data.get("exactMatch"):
        results = [data["exactMatch"]]
    elif data.get("search"):
        results = data["search"]
    else:
        results = []
    for item in results:
        d = item["_source"]
        yield {
            "id": d["id"],
            "title": d["title"],
            "description": d["description"],
            "sourceData": d.get("sourceData", ""),
            "published": d["published"],
            "vhref": f"https://vulners.com/{d['type']}/{d['id']}",
        }


def slugify(value: str) -> str:
    value = re.sub("[^\w\s-]", "", value).strip().lower()
    value = re.sub("[-\s]+", "-", value)
    return value


@click.command("getsploit")
@click.option(
    "-j",
    "--json",
    is_flag=True,
    help="Show result in JSON format",
)
@click.option(
    "-m",
    "--mirror",
    is_flag=True,
    help="Mirror (aka copies) exploits to the current working directory",
)
@click.option(
    "-l",
    "--local",
    is_flag=True,
    help="Perform search in the local database instead of searching online",
)
@click.option(
    "-u",
    "--update",
    is_flag=True,
    help="Update getsploit.db database",
)
@click.option(
    "-s",
    "--set-key",
    is_flag=True,
    help="Set vulners API key",
)
@click.option(
    "-k",
    "--api-key",
    help="Vulners API key",
    envvar="VULNERS_API_KEY",
)
@click.option("-c", "--count", type=click.IntRange(1, 1000), default=10, help="Search limit")
@click.argument("query", nargs=-1)
def main(
    json: bool,
    mirror: bool,
    local: bool,
    update: bool,
    api_key: str | None,
    set_key: bool,
    query: str,
    count: int,
) -> None:
    """Exploit search and download utility"""
    query_value = " ".join(query)
    ctx = Context(api_key)

    if set_key:
        if not query:
            raise click.BadArgumentUsage("Argument for set-key is required")
        ctx.api_key_path.write_text(query_value)
        click.echo("Key updated.")
        return

    if update:
        download_database(ctx)
        click.echo("Database updated.")
        return

    if not query_value:
        raise click.BadArgumentUsage("Query argument is required")

    if local:
        result = list(search_exploit_local(ctx, query_value, count))
    else:
        result = list(search_exploit_online(ctx, query_value, count))

    rows = [{"id": row["id"], "title": row["title"], "url": row["vhref"]} for row in result]
    if json:
        click.echo(orjson.dumps(rows, option=orjson.OPT_INDENT_2))
    else:
        table = texttable.Texttable()
        table.set_cols_dtype(["t", "t", "t"])
        table.set_cols_align(["c", "l", "c"])
        click.echo(f"Total found exploits: {len(rows)}")
        web_search_query = f"bulletinFamily:exploit AND ({query_value})"
        print(web_search_query)
        click.echo(
            f"Web-search URL: https://vulners.com/search?query={urllib.parse.quote_plus(web_search_query)}"
        )
        if rows:
            max_width = max(len(row["url"]) for row in rows)
            table.set_cols_width([20, 30, max_width])
            table.add_rows(
                [["ID", "Exploit Title", "URL"]]
                + [[row["id"], row["title"], row["url"]] for row in rows]
            )
            click.echo(table.draw())

    if mirror:
        mirror_path = pathlib.Path(slugify(query_value))
        mirror_path.mkdir(parents=True, exist_ok=True)
        for row in result:
            exploit_data = row.get("sourceData") or row["description"]
            (mirror_path / row["id"].replace(":", "_")).write_text(exploit_data)


if __name__ == "__main__":
    main()
