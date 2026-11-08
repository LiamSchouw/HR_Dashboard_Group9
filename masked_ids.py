"""HTML views that display masked employee IDs and copy their full values."""

from html import escape


def mask_id(id_no) -> str:
    """Show only the last four digits."""
    value = str(id_no or "")
    return "*" * max(len(value) - 4, 0) + value[-4:]


def id_input(id_no) -> str:
    value = str(id_no or "")
    return (
        '<input class="masked-id" readonly aria-label="ID number; copy to get full ID" '
        'title="Click, then press Ctrl+C (or Command+C) to copy the full ID" '
        f'size="{max(len(value), 4)}" value="{escape(mask_id(value), quote=True)}" '
        f'data-copy-value="{escape(value, quote=True)}">'
    )


def copyable_html(body: str) -> str:
    return """<!doctype html>
<html><head><meta charset="utf-8"><style>
body { margin: 0; color: #4D4D4F; font: 14px 'Segoe UI', Arial, sans-serif; }
.masked-id { font: inherit; color: inherit; background: transparent; border: 0;
  border-radius: 4px; padding: 4px; cursor: text; max-width: 100%; box-sizing: border-box; }
.masked-id:focus { outline: 2px solid #3A8DB3; outline-offset: -2px; }
label { display: block; margin-bottom: 6px; }
.table-wrap { overflow: auto; max-height: 390px; border: 1px solid #DDE3E8;
  border-radius: 12px; background: white; }
table { border-collapse: collapse; width: 100%; white-space: nowrap; }
th, td { padding: 8px 12px; border-bottom: 1px solid #DDE3E8; text-align: left; }
th { position: sticky; top: 0; background: #E3EFF6; z-index: 1; font-weight: 600; }
tr:last-child td { border-bottom: 0; }
</style></head><body>""" + body + """
<script>
document.querySelectorAll('.masked-id').forEach(input => {
  input.addEventListener('focus', () => input.select());
  input.addEventListener('click', () => input.select());
  input.addEventListener('copy', event => {
    event.clipboardData.setData('text/plain', input.dataset.copyValue);
    event.preventDefault();
  });
});
</script></body></html>"""


def employee_table(rows: list) -> str:
    columns = [
        ('First name', 'first_name'), ('Last name', 'last_name'),
        ('Email', 'email_address'), ('Department', 'department'),
        ('Start date', 'start_date'), ('Progress', 'progress'),
    ]
    header = '<th scope="col">ID</th>' + ''.join(
        f'<th scope="col">{label}</th>' for label, _ in columns
    )
    body = ''.join(
        '<tr><td>' + id_input(row.get('id_no')) + '</td>'
        + ''.join(f'<td>{escape(str(row.get(key) or ""))}</td>' for _, key in columns)
        + '</tr>' for row in rows
    )
    return copyable_html(
        '<div class="table-wrap"><table aria-label="All employees">'
        f'<thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>'
    )
