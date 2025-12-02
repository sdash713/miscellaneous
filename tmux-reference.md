# tmux Quick Reference

## Start / Manage Sessions
- **New session:** `tmux new -s mysession`
- **Attach to session:** `tmux attach -t mysession`
- **List sessions:** `tmux ls`
- **Kill session:** `tmux kill-session -t mysession`
- **Detach:** `Ctrl+b d`

## Windows
- **New window:** `Ctrl+b c`
- **Next / Previous window:** `Ctrl+b n` / `Ctrl+b p`
- **Select window by number:** `Ctrl+b <number>`
- **Rename window:** `Ctrl+b ,`

## Panes
- **Split horizontally:** `Ctrl+b "`
- **Split vertically:** `Ctrl+b %`
- **Switch pane:** `Ctrl+b <arrow key>`
- **Close pane:** `Ctrl+b x`

## Resize Panes
- `Ctrl+b :resize-pane -L 10` (left)
- `Ctrl+b :resize-pane -R 10` (right)
- `Ctrl+b :resize-pane -U 10` (up)
- `Ctrl+b :resize-pane -D 10` (down)

## Copy Mode
- **Enter copy mode:** `Ctrl+b [`
- **Scroll:** `↑ / ↓`
- **Exit:** `q`

## Misc
- **Show shortcuts:** `Ctrl+b ?`
- **Reload config:** `Ctrl+b :source-file ~/.tmux.conf`
