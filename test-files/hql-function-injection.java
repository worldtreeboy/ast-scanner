/**
 * FINAL BOSS: HQL/JPQL Function Injection Test Cases
 * The most dangerous 2nd-order SQLi pattern - enables DB takeover or RCE
 */
package com.example.finalboss;

import javax.persistence.*;
import java.text.MessageFormat;

public class HQLFunctionInjectionService {

    @PersistenceContext
    private EntityManager em;

    private UserRepository userRepo;

    // ========================================
    // FINAL BOSS 1: Direct HQL Concat with Entity Value
    // ========================================

    public void saveLastFilter(Long userId, String filter) {
        // Phase 1: Store the payload
        // Payload: "1) = 1 OR 1=dbms_pipe.receive_message('a',10) --"
        User user = userRepo.findById(userId).get();
        user.setLastFilter(filter);
        userRepo.save(user);
    }

    public Object searchWithStoredFilter(Long userId) {
        // Phase 2: Load and use the poisoned filter
        User user = userRepo.findById(userId).get();
        String lastFilter = user.getLastFilter();  // Entity-sourced!

        // FINAL BOSS VULN: HQL with entity value
        // Payload executes: FROM Product WHERE categoryId = 1) = 1 OR 1=dbms_pipe.receive_message('a',10) --
        String hql = "FROM Product WHERE categoryId = " + lastFilter;
        return em.createQuery(hql).getResultList();
    }

    // ========================================
    // FINAL BOSS 2: HQL String Building Pattern
    // ========================================

    public Object dynamicSearch(Long configId) {
        // Load search config from entity
        SearchConfig config = em.find(SearchConfig.class, configId);
        String filterClause = config.getFilterExpression();  // Entity-sourced

        // FINAL BOSS VULN: HQL string building
        String hql = "SELECT p FROM Product p WHERE " + filterClause;
        return em.createQuery(hql).getResultList();
    }

    // ========================================
    // FINAL BOSS 3: String.format HQL Pattern
    // ========================================

    public Object formattedHQL(Long userId) {
        User user = userRepo.findById(userId).get();
        String condition = user.getSearchCondition();  // Entity-sourced

        // FINAL BOSS VULN: String.format doesn't sanitize
        String hql = String.format("FROM Order WHERE %s", condition);
        return em.createQuery(hql).getResultList();
    }

    // ========================================
    // FINAL BOSS 4: Entity Getter in HQL Context
    // ========================================

    public Object reportByUserPreference(Long userId) {
        // Direct entity getter in HQL context
        User user = userRepo.findById(userId).get();

        // FINAL BOSS VULN: Getter value goes directly into HQL
        String hql = "FROM Report WHERE status = '" + user.getPreferredStatus() + "'";
        return em.createQuery(hql).getResultList();
    }

    // ========================================
    // FINAL BOSS 5: MessageFormat Pattern (Rare but Deadly)
    // ========================================

    public Object messageFormatHQL(Long configId) {
        Config config = em.find(Config.class, configId);
        String filterCol = config.getFilterColumn();

        // FINAL BOSS VULN: MessageFormat HQL
        String hql = MessageFormat.format("FROM Entity WHERE {0} = 1", filterCol);
        return em.createQuery(hql).getResultList();
    }

    // ========================================
    // FINAL BOSS 6: Multi-Step HQL Building
    // ========================================

    public Object complexHQLBuild(Long userId) {
        User user = userRepo.findById(userId).get();
        String sortOrder = user.getSortPreference();  // Entity-sourced

        StringBuilder hql = new StringBuilder();
        hql.append("FROM Product p ");
        hql.append("WHERE p.active = true ");
        hql.append("ORDER BY p.");
        hql.append(sortOrder);  // FINAL BOSS: Injected into ORDER BY

        return em.createQuery(hql.toString()).getResultList();
    }

    // ========================================
    // TIME-BASED EXFIL PATTERNS
    // ========================================

    public Object timeBased(Long userId) {
        // Payload: "1 AND 1=dbms_pipe.receive_message('RDS',10)"
        // Or for PostgreSQL: "1; SELECT pg_sleep(10)--"
        User user = userRepo.findById(userId).get();
        String condition = user.getCondition();

        // Server hangs for 10 seconds = vulnerability confirmed
        String hql = "FROM Audit WHERE id = " + condition;
        return em.createQuery(hql).getResultList();
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================

    public Object safeParameterized(Long userId, String status) {
        // Safe: Using named parameters
        return em.createQuery("FROM Product WHERE status = :status")
            .setParameter("status", status)
            .getResultList();
    }

    public Object safePositionalParam(Long productId) {
        // Safe: Positional parameter
        return em.createQuery("FROM Product WHERE id = ?1")
            .setParameter(1, productId)
            .getResultList();
    }

    public Object safeTypedQuery(String category) {
        // Safe: Using TypedQuery with params
        TypedQuery<Product> query = em.createQuery(
            "FROM Product p WHERE p.category = :cat", Product.class);
        query.setParameter("cat", category);
        return query.getResultList();
    }
}

// Entity classes
@Entity class User {
    @Id private Long id;
    private String lastFilter;
    private String searchCondition;
    private String preferredStatus;
    private String sortPreference;
    private String condition;
    public String getLastFilter() { return lastFilter; }
    public String getSearchCondition() { return searchCondition; }
    public String getPreferredStatus() { return preferredStatus; }
    public String getSortPreference() { return sortPreference; }
    public String getCondition() { return condition; }
    public void setLastFilter(String f) { this.lastFilter = f; }
}

@Entity class SearchConfig {
    @Id private Long id;
    private String filterExpression;
    public String getFilterExpression() { return filterExpression; }
}

@Entity class Config {
    @Id private Long id;
    private String filterColumn;
    public String getFilterColumn() { return filterColumn; }
}

interface UserRepository { User findById(Long id); }
