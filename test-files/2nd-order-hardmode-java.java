/**
 * HARD MODE: 2nd-Order SQL Injection Test Cases for Java
 * Tests: Hibernate Criteria API, Table name injection, Entity-sourced properties
 * These patterns break most scanners because they look like "safe" ORM code
 */
package com.example.hardmode;

import javax.persistence.*;
import javax.persistence.criteria.*;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public class HardModeVulnerableService {

    @PersistenceContext
    private EntityManager em;

    private FilterRepository filterRepo;
    private TenantRepository tenantRepo;

    // ========================================
    // HARD MODE 1: Hibernate Criteria API Injection
    // Developers think Criteria API is "injection-proof" - WRONG
    // ========================================

    public void saveCustomFilter(Long userId, String propertyName) {
        // Phase 1: Store filter property name
        // Payload: "id) = 1 OR (1=1"
        Filter filter = new Filter();
        filter.setPropertyName(propertyName);
        filterRepo.save(filter);
    }

    public List<User> searchWithStoredFilter(Long filterId) {
        // Phase 2: Load stored filter property
        Filter savedFilter = filterRepo.findById(filterId).get();
        String property = savedFilter.getPropertyName();  // Returns payload

        // HARD MODE VULN: Criteria API with entity-sourced property
        // This looks safe but root.get() is a STRUCTURAL SINK
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<User> cq = cb.createQuery(User.class);
        Root<User> root = cq.from(User.class);

        // THE SINK: root.get(property) where property = "id) = 1 OR (1=1"
        cq.where(cb.equal(root.get(property), 1));

        return em.createQuery(cq).getResultList();
    }

    public List<User> sortByStoredPreference(Long prefId) {
        // Load sort column from user preference entity
        UserPreference pref = em.find(UserPreference.class, prefId);
        String sortColumn = pref.getSortColumn();  // Entity-sourced

        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<User> cq = cb.createQuery(User.class);
        Root<User> root = cq.from(User.class);

        // HARD MODE VULN: cb.asc() with entity-sourced column
        cq.orderBy(cb.asc(root.get(sortColumn)));

        return em.createQuery(cq).getResultList();
    }

    public List<Product> dynamicOrderDesc(Long configId) {
        // Load from config entity
        Config config = em.find(Config.class, configId);
        String orderField = config.getOrderField();

        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Product> cq = cb.createQuery(Product.class);
        Root<Product> root = cq.from(Product.class);

        // HARD MODE VULN: cb.desc() with entity-sourced field
        cq.orderBy(cb.desc(root.get(orderField)));

        return em.createQuery(cq).getResultList();
    }

    public List<User> complexCriteriaQuery(Long filterId) {
        Filter filter = filterRepo.findById(filterId).get();
        String filterProp = filter.getPropertyName();
        String sortProp = filter.getSortProperty();

        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<User> cq = cb.createQuery(User.class);
        Root<User> root = cq.from(User.class);

        // HARD MODE VULN: Multiple Criteria sinks with entity values
        Predicate pred = cb.equal(root.get(filterProp), "active");
        cq.where(pred);
        cq.orderBy(cb.asc(root.get(sortProp)));

        return em.createQuery(cq).getResultList();
    }

    // ========================================
    // HARD MODE 2: Multi-Tenant Table Name Injection
    // The "Bunker Buster" in Java
    // ========================================

    public void saveTenantTable(Long tenantId, String tableName) {
        // Phase 1: Store tenant's table name
        // Payload: "users --" or "users; DROP TABLE admins;--"
        Tenant tenant = tenantRepo.findById(tenantId).get();
        tenant.setTableName(tableName);
        tenantRepo.save(tenant);
    }

    public void cleanupTenantData(Long tenantId) {
        // Phase 2: Load table name from tenant entity
        Tenant tenant = tenantRepo.findById(tenantId).get();
        String tableName = tenant.getTableName();

        // HARD MODE VULN: Native query with entity-sourced table name
        String sql = "DELETE FROM " + tableName + " WHERE created_at < ?";
        em.createNativeQuery(sql).setParameter(1, "2023-01-01").executeUpdate();
    }

    public void updateTenantEntity(Long tenantId) {
        String table = tenantRepo.findById(tenantId).get().getTableName();

        // HARD MODE VULN: UPDATE with entity-sourced table
        em.createNativeQuery("UPDATE " + table + " SET archived = true").executeUpdate();
    }

    public void insertIntoTenantTable(Long tenantId, String data) {
        // getTableName() is the source
        String tbl = em.find(TenantConfig.class, tenantId).getTableName();

        // HARD MODE VULN: INSERT with entity table name
        em.createNativeQuery("INSERT INTO " + tbl + " (data) VALUES (?)").setParameter(1, data).executeUpdate();
    }

    // ========================================
    // HARD MODE 3: Entity Getter Chain
    // Deeper entity traversal
    // ========================================

    public void deepEntityChain(Long userId) {
        // Chain: User -> Profile -> Settings -> column name
        User user = em.find(User.class, userId);
        String dynamicCol = user.getProfile().getSettings().getDynamicColumn();

        // HARD MODE VULN: Entity getter chain to Criteria
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Product> cq = cb.createQuery(Product.class);
        Root<Product> root = cq.from(Product.class);

        cq.where(cb.like(root.get(dynamicCol), "%test%"));

        em.createQuery(cq).getResultList();
    }

    // ========================================
    // COMBINED: Criteria + Table + Native
    // The Ultimate Java Test
    // ========================================

    public void ultimateJavaVuln(Long configId) {
        // Load multi-field config from entity
        MultiConfig config = em.find(MultiConfig.class, configId);
        String tableName = config.getTargetTable();
        String filterColumn = config.getFilterColumn();
        String orderColumn = config.getOrderColumn();

        // TRIPLE WHAMMY:
        // 1. Table name injection
        // 2. Criteria filter injection
        // 3. Criteria order injection
        String sql = "SELECT * FROM " + tableName + " WHERE " + filterColumn + " = ? ORDER BY " + orderColumn;
        em.createNativeQuery(sql).setParameter(1, "active").getResultList();
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================

    public List<User> safeCriteriaQuery() {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<User> cq = cb.createQuery(User.class);
        Root<User> root = cq.from(User.class);

        // Safe: Literal property name, not from entity
        cq.where(cb.equal(root.get("status"), "active"));
        cq.orderBy(cb.asc(root.get("createdAt")));

        return em.createQuery(cq).getResultList();
    }

    public void safeParameterizedQuery(String status) {
        // Safe: Using named parameters
        em.createQuery("SELECT u FROM User u WHERE u.status = :status")
            .setParameter("status", status)
            .getResultList();
    }

    public void safeTableWithValidation(Long tenantId) {
        String table = tenantRepo.findById(tenantId).get().getTableName();

        // Safe: Whitelist validation
        if (!List.of("logs", "events", "metrics").contains(table)) {
            throw new IllegalArgumentException("Invalid table");
        }
        em.createNativeQuery("SELECT * FROM " + table).getResultList();
    }
}

// Entity classes
@Entity class Filter {
    @Id private Long id;
    private String propertyName;
    private String sortProperty;
    public String getPropertyName() { return propertyName; }
    public String getSortProperty() { return sortProperty; }
    public void setPropertyName(String p) { this.propertyName = p; }
}

@Entity class Tenant {
    @Id private Long id;
    private String tableName;
    public String getTableName() { return tableName; }
    public void setTableName(String t) { this.tableName = t; }
}

@Entity class TenantConfig {
    @Id private Long id;
    private String tableName;
    public String getTableName() { return tableName; }
}

@Entity class UserPreference {
    @Id private Long id;
    private String sortColumn;
    public String getSortColumn() { return sortColumn; }
}

@Entity class Config {
    @Id private Long id;
    private String orderField;
    public String getOrderField() { return orderField; }
}

@Entity class MultiConfig {
    @Id private Long id;
    private String targetTable;
    private String filterColumn;
    private String orderColumn;
    public String getTargetTable() { return targetTable; }
    public String getFilterColumn() { return filterColumn; }
    public String getOrderColumn() { return orderColumn; }
}

interface FilterRepository extends JpaRepository<Filter, Long> {}
interface TenantRepository extends JpaRepository<Tenant, Long> {}
