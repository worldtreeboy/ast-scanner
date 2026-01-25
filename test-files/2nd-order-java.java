/**
 * 2nd-Order SQL Injection Test Cases for Java
 * Tests: Hibernate/JPA/JDBC with entity-sourced values
 */
package com.example.vulnerable;

import javax.persistence.*;
import org.springframework.jdbc.core.JdbcTemplate;
import java.sql.*;

public class VulnerableItemService {

    @PersistenceContext
    private EntityManager entityManager;

    private JdbcTemplate jdbcTemplate;
    private CategoryRepository categoryRepo;

    // ========================================
    // PHASE 1: Safe storage (no vuln here)
    // ========================================
    public void saveCategory(Long id, String name) {
        // Safe: JPA entity save
        Category category = new Category();
        category.setName(name);  // Payload: "1') OR 1=1; --"
        categoryRepo.save(category);
    }

    // ========================================
    // 2ND-ORDER: DELETE with entity value
    // ========================================
    public void cleanupItemsByCategory(Long categoryId) {
        // Phase 2: Load the poisoned category name from DB
        String categoryName = categoryRepo.findById(categoryId).get().getName();

        // VULNERABLE: Native query with entity-sourced value
        // Payload stored: "1') OR 1=1; --" deletes ALL items
        String sql = "DELETE FROM items WHERE category_id = (SELECT id FROM categories WHERE name = '" + categoryName + "')";
        Query query = entityManager.createNativeQuery(sql);
        query.executeUpdate();
    }

    public void deleteByStoredFilter(Long configId) {
        // Load filter from config entity
        String filterValue = entityManager.find(Config.class, configId).getFilterColumn();

        // VULNERABLE: 2nd-order DELETE via JdbcTemplate
        jdbcTemplate.execute("DELETE FROM records WHERE " + filterValue);
    }

    // ========================================
    // 2ND-ORDER: UPDATE with entity value
    // ========================================
    public void updateStatusByProfile(Long userId) {
        // Fetch stored value from user profile
        String storedStatus = entityManager.find(UserProfile.class, userId).getCustomStatus();

        // VULNERABLE: UPDATE with entity-sourced value
        String updateSql = "UPDATE accounts SET flag = 1 WHERE status = '" + storedStatus + "'";
        entityManager.createNativeQuery(updateSql).executeUpdate();
    }

    public void massUpdateByCategory(Long catId) {
        // Get category from repository
        String catName = categoryRepo.findById(catId).getName();

        // VULNERABLE: jdbcTemplate.update with entity value
        jdbcTemplate.update("UPDATE products SET active = 0 WHERE category = '" + catName + "'");
    }

    // ========================================
    // 2ND-ORDER: StringBuilder pattern
    // ========================================
    public void deleteWithStringBuilder(Long settingId) {
        // Load condition from settings entity
        String condition = entityManager.find(Setting.class, settingId).getDeleteCondition();

        // VULNERABLE: StringBuilder with entity-sourced value
        StringBuilder sql = new StringBuilder();
        sql.append("DELETE FROM temp_data WHERE ");
        sql.append(condition);  // 2nd-order injection point
        entityManager.createNativeQuery(sql.toString()).executeUpdate();
    }

    // ========================================
    // 2ND-ORDER: JDBC ResultSet pattern
    // ========================================
    public void processFromResultSet(Connection conn, int configId) throws SQLException {
        // Fetch from ResultSet (Phase 1 stored value)
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT filter_col FROM config WHERE id = " + configId);
        rs.next();
        String filterColumn = rs.getString("filter_col");

        // VULNERABLE: DELETE with ResultSet-sourced value
        conn.createStatement().executeUpdate("DELETE FROM logs WHERE " + filterColumn);
    }

    // ========================================
    // 1ST-ORDER (Direct) for comparison
    // ========================================
    public void directDelete(String userInput) {
        // 1st-order: Method param directly in query
        String sql = "DELETE FROM items WHERE id = " + userInput;
        entityManager.createNativeQuery(sql).executeUpdate();
    }

    public void directUpdate(String category) {
        // 1st-order: Direct param in UPDATE
        jdbcTemplate.update("UPDATE products SET stock = 0 WHERE category = '" + category + "'");
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================
    public void safeDelete(Long itemId) {
        // Parameterized query - safe
        entityManager.createNativeQuery("DELETE FROM items WHERE id = ?1")
            .setParameter(1, itemId)
            .executeUpdate();
    }

    public void safeUpdate(String status, Long userId) {
        // Named parameter - safe
        entityManager.createQuery("UPDATE User u SET u.status = :status WHERE u.id = :id")
            .setParameter("status", status)
            .setParameter("id", userId)
            .executeUpdate();
    }

    public void safeJdbcDelete(Long id) {
        // PreparedStatement - safe
        jdbcTemplate.update("DELETE FROM records WHERE id = ?", id);
    }
}

// Entity classes for context
@Entity
class Category {
    @Id
    private Long id;
    private String name;
    public String getName() { return name; }
    public void setName(String n) { this.name = n; }
}

@Entity
class Config {
    @Id
    private Long id;
    private String filterColumn;
    public String getFilterColumn() { return filterColumn; }
}

@Entity
class UserProfile {
    @Id
    private Long id;
    private String customStatus;
    public String getCustomStatus() { return customStatus; }
}

@Entity
class Setting {
    @Id
    private Long id;
    private String deleteCondition;
    public String getDeleteCondition() { return deleteCondition; }
}
