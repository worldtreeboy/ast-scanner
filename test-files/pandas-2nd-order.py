"""
2nd-Order Code Injection Test Cases - Pandas df.query()/eval()
The pandas query() and eval() methods execute string expressions as code.
When the expression comes from the database, attackers can inject code.

Payload example stored in DB: "@__builtins__['__import__']('os').system('id')"
"""
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

# ==================================================
# VULNERABLE PATTERNS (Should detect)
# ==================================================

def vuln_query_from_sqlalchemy(session: Session, user_id: int):
    """Pattern 1: SQLAlchemy query result used in df.query()"""
    # Phase 1: Load user's saved filter from database
    user = session.query(User).filter(User.id == user_id).first()
    filter_expr = user.saved_filter  # Entity-sourced!

    # Phase 2: Apply filter to DataFrame
    df = pd.read_csv("data.csv")
    # VULN: df.query() evaluates the string as Python expression
    # Payload: "@__builtins__['exec'](__import__('base64').b64decode('...'))"
    result = df.query(filter_expr)
    return result


def vuln_eval_from_django(request):
    """Pattern 2: Django ORM result used in df.eval()"""
    from myapp.models import ReportConfig

    # Phase 1: Load report config from database
    config = ReportConfig.objects.get(id=request.GET['config_id'])
    calc_expr = config.calculation_formula  # DB-sourced!

    # Phase 2: Apply calculation to DataFrame
    df = pd.DataFrame({"sales": [100, 200], "costs": [50, 75]})
    # VULN: df.eval() evaluates the string as code
    # Payload: "@pd.io.common.os.system('whoami')"
    df.eval(calc_expr, inplace=True)
    return df


def vuln_pd_eval_from_cursor(cursor, filter_id: int):
    """Pattern 3: Raw cursor fetch used in pd.eval()"""
    # Phase 1: Fetch filter expression from database
    cursor.execute("SELECT expression FROM filters WHERE id = %s", (filter_id,))
    row = cursor.fetchone()
    expr = row['expression']  # DB-sourced!

    # Phase 2: Use in pandas eval
    df = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
    # VULN: pd.eval() executes arbitrary Python code
    result = pd.eval(expr, local_dict={'df': df})
    return result


def vuln_query_from_read_sql(engine, report_id: int):
    """Pattern 4: pandas.read_sql() result used in query()"""
    # Phase 1: Load saved queries from database (ironic!)
    saved_queries = pd.read_sql(
        "SELECT * FROM saved_queries WHERE report_id = %s",
        engine, params=(report_id,)
    )
    filter_expr = saved_queries.iloc[0]['filter_expression']  # DB-sourced!

    # Phase 2: Apply to another DataFrame
    data = pd.read_csv("data.csv")
    # VULN: Using DB value in query()
    result = data.query(filter_expr)
    return result


def vuln_chained_attribute_access(session: Session):
    """Pattern 5: Chained attribute access from entity"""
    # Phase 1: Load dashboard config
    dashboard = session.query(Dashboard).first()
    widget = dashboard.widgets  # Entity-sourced
    filter_text = widget.filter_config  # Chained access

    # Phase 2: Use in query
    df = pd.DataFrame({"x": [1, 2, 3]})
    # VULN: DB value used in query()
    return df.query(filter_text)


def vuln_dict_access_from_fetchall(cursor):
    """Pattern 6: Dictionary access from cursor results"""
    cursor.execute("SELECT * FROM configs")
    rows = cursor.fetchall()

    for row in rows:
        expr = row['eval_expression']  # DB-sourced via dict access
        df = pd.DataFrame({"val": [1, 2, 3]})
        # VULN: Each row's expression is evaluated
        df.eval(expr)


# ==================================================
# SAFE PATTERNS (Should NOT detect)
# ==================================================

def safe_literal_query():
    """Safe: Literal string query expression"""
    df = pd.DataFrame({"age": [25, 30, 35], "salary": [50000, 60000, 70000]})
    # Safe: hardcoded query string
    result = df.query("age > 25 and salary > 55000")
    return result


def safe_validated_input():
    """Safe: Whitelisted/validated input"""
    ALLOWED_COLUMNS = {"age", "salary", "department"}

    # Even if from DB, if validated against whitelist
    user_column = "age"  # pretend from DB but validated
    if user_column not in ALLOWED_COLUMNS:
        raise ValueError("Invalid column")

    df = pd.DataFrame({"age": [25, 30], "salary": [50000, 60000]})
    # Safe after validation
    result = df.query(f"{user_column} > 25")
    return result


def safe_f_string_with_literal():
    """Safe: f-string but with literal parts only"""
    df = pd.DataFrame({"x": [1, 2, 3]})
    threshold = 2  # from request, but just a number
    # Safe: only interpolating validated number
    result = df.query(f"x > {int(threshold)}")
    return result


def safe_parameterized_sql():
    """Safe: Parameterized SQL (not using df.query with DB data)"""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Safe: Using parameterized queries
    cursor.execute("SELECT * FROM users WHERE id = ?", (1,))
    return cursor.fetchall()
