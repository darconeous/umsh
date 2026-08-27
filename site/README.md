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
Links into `/docs/protocol/` and `/docs/rust/` will 404 there—Zola does not
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
| `data/hardware.toml` | Every supported board—see below |
| `sass/site.scss` | All styling. Brand colors at the top. |
| `static/` | Images, favicons, `nav.js`, and `CNAME` |

## Editing content

Most copy is Markdown in `content/`. Two pages are different:

- **The landing page** keeps every word in the front matter of
  `content/_index.md`; `templates/index.html` is markup only. Prose fields
  are rendered as Markdown, so links and emphasis work in them, and the
  pillars, the smaller cards, the comparison tables, and the getting-started
  steps are all arrays—adding or reordering one is a content edit. Keep the
  comparison tables in step with the comparison chapters of the
  specification.
- **Hardware and flashing** are both generated from `data/hardware.toml`.

## Writing a post

Posts are Markdown files in `content/blog/`, one per post:

```toml
+++
title = "What landed"
description = "One sentence. It runs under the title on the index, in the feed, and on social cards."
date = 2026-08-10

[extra]
image = "images/blog/what-landed.png"
+++
```

The filename is the URL—`content/blog/what-landed.md` publishes at
`/blog/what-landed/`—so rename before publishing, not after. Posts list newest
first. `draft = true` keeps one out of the build entirely.

`extra.image` is the post's social card, and it is the only front matter field
that is optional: a post without one falls back to the site-wide `og-card.png`.
The path is relative to `static/` and takes no leading slash, because the
template hands it to `get_url`—scrapers need an absolute URL. Make it
**1200×630**, matching `og-card.png`. `twitter:card` is `summary_large_image`
sitewide, so platforms crop to 1.91:1 and a taller image loses its top and
bottom. This is a separate export from any image in the post body; an image
placed in the body has no effect on the card.

Body images go in `static/images/blog/` and are referenced from the site root
(`![Alt](/images/blog/what-landed.png)`). The prose column is 736px wide, so
export at about 1500px for 2× displays; `img { max-width: 100% }` handles the
rest and no wrapper markup is needed.

Social platforms cache cards aggressively. Once a URL has been scraped,
changing the image will not refresh it without a manual purge in that
platform's own debugger, and the file has to be live on umsh.dev before the
first scrape—deploy before sharing the link.

`/blog/atom.xml` is the only feed the site publishes, which is why
`generate_feeds` is off in `config.toml` and on in `content/blog/_index.md`;
turning it on globally would put the FAQ and the terms page in the feed.

There is no pagination. If the list ever grows enough to want it, `paginate_by`
on the section switches it on, and `templates/blog.html` then has to loop over
`paginator.pages` instead of `section.pages`.

## Adding or changing a board

Edit `data/hardware.toml`. A board's `id` matches the preset in
`scripts/flash.py` and the `make flash-<id>` target suffix—keep all three in
step, because the web flasher will key off the same identifier. Flash
constants (UF2 family, application base, bootloader volume) are mirrored from
that script, which stays authoritative.

Set `status` to `proven`, `partial`, `untested`, or `planned`; the badge on the
card follows from it. A board with no `[boards.flash]` table is one no firmware
exists for: its flash button is disabled and it is left off the flashing page. Put the photo in `static/images/boards/`, name it in the
`photo` field, and record its source in that directory's `CREDITS.md`. A board
with an empty `photo` renders a labeled placeholder rather than a broken
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
refuses to commit a tree with no `CNAME`—publishing without that file makes
GitHub drop the custom domain.

```bash
make gh-pages-site
```

`make gh-pages-site` deploys the site and the specification and leaves
`docs/rust` as already published. The rustdoc build is the slow half of a
deploy—it wipes `target/doc` first, so it never gets to be incremental—and the
API docs rarely move when a page of site copy does. Use the full `make
gh-pages` when they do.

The published root belongs to Zola. `docs/protocol`, `docs/rust`,
`firmware/` (release artifacts) and `tools/` are preserved across deploys;
anything else at the root is replaced. A new top-level directory that Zola
does not generate has to be added to the preserve list in the Makefile.
