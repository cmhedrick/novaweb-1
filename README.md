# novaweb
A timesheet and invoice generation system for Workers Co-Operatives.

1. Rename default_settings.cfg.example to default_settings.cfg and edit.

1. To create the schema for upd:
    ```py
    >>> import novaweb
    >>> upd.model.db.create_all(bind='novaweb')
    ```
1. To load test data...
