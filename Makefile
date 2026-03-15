.PHONY: docs docs-serve gh-pages

docs:
	mdbook build docs/protocol/

docs-serve:
	mdbook serve docs/protocol/

gh-pages: docs
	@if ! git show-ref --quiet refs/heads/gh-pages; then \
		echo "Creating gh-pages branch..."; \
		git worktree add /tmp/umsh-gh-pages --orphan -b gh-pages; \
	else \
		echo "Updating gh-pages branch..."; \
		git worktree add /tmp/umsh-gh-pages gh-pages 2>/dev/null || true; \
	fi
	rm -rf /tmp/umsh-gh-pages/docs/protocol
	mkdir -p /tmp/umsh-gh-pages/docs/protocol
	cp -r docs/protocol/book/* /tmp/umsh-gh-pages/docs/protocol/
	cd /tmp/umsh-gh-pages && \
		git add -A && \
		git diff --cached --quiet || git commit -m "Update GitHub Pages"
	git worktree remove /tmp/umsh-gh-pages
	@echo "gh-pages branch updated. Push with: git push origin gh-pages"
