# 2nd-Order SQL Injection Test Cases for Ruby/Rails
# Tests: structural sinks, calculation sinks, destructive sinks

class ReportsController < ApplicationController

  # ========================================
  # PHASE 1: Safe storage (no vuln here)
  # ========================================
  def save_preference
    # User saves sorting preference - parameterized, safe storage
    current_user.update(sort_pref: params[:sort_by])
  end

  # ========================================
  # 2ND-ORDER: Structural Injection (ORDER BY)
  # ========================================
  def generate_report
    # 2nd-order: Load poisoned value from DB
    user_pref = User.find(1).sort_pref

    # VULNERABLE: Database value in order()
    @orders = Order.order("#{user_pref} ASC")
    # Payload: "name); DROP TABLE users;--" executes
  end

  def sorted_users
    # 2nd-order via reorder()
    sort_column = current_user.sort_column

    # VULNERABLE: reorder() overwrites ORDER BY clause
    User.reorder(sort_column)
  end

  # ========================================
  # 2ND-ORDER: Calculation Injection (No SELECT)
  # ========================================
  def count_by_preference
    # Load column name from database
    column_pref = User.find(params[:id]).column_preference

    # VULNERABLE: count() accepts raw SQL for column name
    # Payload: "price); DROP TABLE users;--"
    total = Order.count(column_pref)
  end

  def sum_report
    # 2nd-order via sum()
    sum_column = Setting.find_by(key: 'sum_field').value

    # VULNERABLE: sum() with db-sourced column
    Invoice.sum(sum_column)
  end

  def stats_by_group
    # 2nd-order GROUP BY injection
    group_pref = UserPreference.first.group_column

    # VULNERABLE: group() allows UNION/SLEEP attacks
    Product.group(group_pref).count
  end

  # ========================================
  # 2ND-ORDER: Destructive Injection (Table Wipeout)
  # ========================================
  def cleanup_by_category
    # Load category from database
    category = Category.find(params[:id]).name

    # VULNERABLE: delete_all with db-sourced condition
    # Payload: "1 OR 1=1" deletes ALL messages
    Message.delete_all("category = '#{category}'")
  end

  def purge_old_data
    # 2nd-order destroy_all
    filter_condition = AuditLog.last.filter_value

    # VULNERABLE: destroy_all table wipeout
    Record.destroy_all("status = '#{filter_condition}'")
  end

  # ========================================
  # 1ST-ORDER (Direct) for comparison
  # ========================================
  def direct_order_injection
    # 1st-order: Direct params in order()
    @users = User.order("#{params[:sort]} DESC")
  end

  def direct_delete_injection
    # 1st-order: Direct params in delete_all
    Message.delete_all("user_id = #{params[:id]}")
  end

  def direct_calculation
    # 1st-order: params in sum()
    Product.sum(params[:column])
  end

  # ========================================
  # SAFE PATTERNS (Should NOT flag)
  # ========================================
  def safe_order
    # Symbol notation - safe
    User.order(:name)
  end

  def safe_count
    # Symbol notation - safe
    Order.count(:id)
  end

  def safe_delete
    # Parameterized - safe
    Message.where(user_id: params[:id]).delete_all
  end
end
