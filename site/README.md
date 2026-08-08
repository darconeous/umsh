# umsh.dev

The project website. Built with [Zola](https://www.getzola.org/), published to
the `gh-pages` branch by `make gh-pages`, and served by GitHub Pages at
<https://umsh.dev>.

## Working on it

```bash
brew install zola
make site-serve
```

That serves the site on <http://localhost:1111> and rebuilds as you edit.
Links into `/docs/protocol/` and `/docs/rust/` will 404 there — Zola does not
own those trees. To see everything together:

```bash
make site-preview
```

```bash
python3 -m http.server 8000 -d target/site-preview
```

`make site-check` validates internal links without rendering.

**Zola 0.23 or newer is required.** That release moved to Tera v2, which
dropped macros, `{% import %}`, `self::` block calls, and the `filter` filter.
The templates here are deliberately written with plain loops and conditionals
so they do not depend on any of that.

## Where things live

| Path | What it is |
|---|---|
| `config.toml` | Site config, the top navigation, and shared URLs under `[extra]` |
| `content/` | One file per page. Front matter picks the template. |
| `templates/` | `base.html` holds the header and footer; the rest extend it |
| `data/hardware.toml` | Every supported board — see below |
| `sass/site.scss` | All styling. Brand colors at the top. |
| `static/` | Images, favicons, `nav.js`, and `CNAME` |

## Editing content

Most copy is Markdown in `content/`. Two pages are different:

- **The landing page** keeps its copy in the front matter of
  `content/_index.md` — the tagline, the six feature pillars, and the three
  smaller cards are arrays there, so adding or reordering a pillar is a
  content edit rather than a template edit. The comparison tables live in
  `templates/index.html`, since they are structure as much as text; keep them
  in step with the comparison chapters of the specification.
- **Hardware and flashing** are both generated from `data/hardware.toml`.

## Adding or changing a board

Edit `data/hardware.toml`. A board's `id` matches the preset in
`scripts/flash.py` and the `make flash-<id>` target suffix — keep all three in
step, because the web flasher will key off the same identifier. Flash
constants (UF2 family, application base, bootloader volume) are mirrored from
that script, which stays authoritative.

Set `status` to `proven`, `partial`, or `untested`; the badge on the card
follows from it. Put the photo in `static/images/boards/`, name it in the
`photo` field, and record its source in that directory's `CREDITS.md`. A board
with an empty `photo` renders a labelled placeholder rather than a broken
image.

## Publishing

```bash
make gh-pages
```

```bash
git push origin gh-pages
```

`make gh-pages` rebuilds the site, the specification, and the Rust API docs,
then assembles them in a worktree of the `gh-pages` branch. It fast-forwards
onto `origin/gh-pages` first and stops if the branches have diverged, and it
refuses to commit a tree with no `CNAME` — publishing without that file makes
GitHub drop the custom domain.

The published root belongs to Zola. `docs/protocol`, `docs/rust`,
`firmware/` (release artifacts) and `tools/` are preserved across deploys;
anything else at the root is replaced. A new top-level directory that Zola
does not generate has to be added to the preserve list in the Makefile.
