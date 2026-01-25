/**
 * EVASIVE JAVA SQL INJECTION TEST CASES
 * These patterns bypass 99% of SAST tools.
 *
 * Attack Vectors:
 * 1. Reflection Ghost - Method.invoke() hides executeQuery()
 * 2. Hex-Encoded Bypass - unhex()/decode() passthrough
 * 3. Annotation Trap - @Query with SpEL injection
 * 4. StringBuilder Chain - Taint through append() methods
 * 5. Lambda/Stream Evasion - Functional taint tunneling
 * 6. Dynamic Class Loading - ClassLoader injection
 */
package com.example.evasive;

import javax.persistence.*;
import java.lang.reflect.*;
import java.sql.*;
import java.util.*;
import java.util.stream.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public class EvasiveSQLiService {

    private Connection connection;
    private EntityManager em;
    private ConfigRepository configRepo;
    private UserRepository userRepo;

    // ========================================
    // PATTERN 1: REFLECTION GHOST
    // Scanner sees Method.invoke(), not executeQuery()
    // ========================================

    public ResultSet reflectionGhost(Long userId) throws Exception {
        // 2nd-order: Load method names from DB config
        Config config = configRepo.findById(1L).get();
        String className = config.getDriverClass();     // "java.sql.Statement"
        String methodName = config.getExecMethod();     // "executeQuery"

        // 2nd-order: Poisoned query from user entity
        User user = userRepo.findById(userId).get();
        String poisonedQuery = user.getSavedQuery();    // Entity-sourced!

        // EVASIVE: Reflection hides the sink
        Class<?> clazz = Class.forName(className);
        Statement statement = connection.createStatement();
        Method method = clazz.getMethod(methodName, String.class);

        // 💀 CRITICAL: Tainted data flows to invoke()
        return (ResultSet) method.invoke(statement, poisonedQuery);
    }

    public Object reflectionWithGetDeclaredMethod(Long configId) throws Exception {
        Config config = configRepo.findById(configId).get();
        String query = config.getDynamicQuery();  // Entity-sourced!

        // Even more evasive - getDeclaredMethod
        Statement stmt = connection.createStatement();
        Method m = Statement.class.getDeclaredMethod("executeQuery", String.class);
        m.setAccessible(true);

        // 💀 CRITICAL: invoke() with tainted query
        return m.invoke(stmt, query);
    }

    // ========================================
    // PATTERN 2: HEX-ENCODED BYPASS
    // unhex()/decode() doesn't sanitize!
    // ========================================

    public List<?> hexEncodedBypass(String hexPayload) {
        // Attacker sends: 53454c454354202a2046524f4d207573657273
        // Which decodes to: SELECT * FROM users

        // EVASIVE: Scanner might think unhex() sanitizes
        // But it's just a DB-level decoder - taint passes through!
        String query = "SELECT * FROM products WHERE category = unhex('" + hexPayload + "')";
        return em.createNativeQuery(query).getResultList();
    }

    public List<?> base64EncodedBypass(Long userId) {
        User user = userRepo.findById(userId).get();
        String encodedFilter = user.getEncodedFilter();  // Base64 in DB

        // EVASIVE: from_base64() is a passthrough, not sanitizer
        String query = "SELECT * FROM items WHERE filter = from_base64('" + encodedFilter + "')";
        return em.createNativeQuery(query).getResultList();
    }

    public List<?> convertUsingBypass(Long configId) {
        Config config = configRepo.findById(configId).get();
        String hexData = config.getHexFilter();  // Entity-sourced!

        // EVASIVE: CONVERT with USING doesn't sanitize
        String query = "SELECT * FROM data WHERE col = CONVERT(" + hexData + " USING utf8)";
        return em.createNativeQuery(query).getResultList();
    }

    // ========================================
    // PATTERN 3: CHAINED STRINGBUILDER
    // Taint lost through method boundaries
    // ========================================

    public void stringBuilderChain(Long userId) throws SQLException {
        User user = userRepo.findById(userId).get();
        String taintedId = user.getCustomId();  // Entity-sourced!

        StringBuilder sb = new StringBuilder("SELECT * FROM accounts WHERE id = ");

        // Taint flows into builder through helper method
        appendTaintedData(sb, taintedId);

        // Later in code...
        String finalSql = sb.toString();

        // 💀 CRITICAL: StringBuilder contained tainted data
        connection.createStatement().executeQuery(finalSql);
    }

    private void appendTaintedData(StringBuilder builder, String data) {
        // Taint must propagate through this method!
        builder.append(data);
    }

    public void multiMethodBuilderChain(Long userId) throws SQLException {
        User user = userRepo.findById(userId).get();

        StringBuilder sb = new StringBuilder();
        buildSelectClause(sb);
        buildWhereClause(sb, user.getFilterColumn());  // Taint enters here
        buildOrderClause(sb, user.getSortPreference()); // More taint

        // 💀 CRITICAL: Multiple tainted appends
        connection.createStatement().executeQuery(sb.toString());
    }

    private void buildSelectClause(StringBuilder sb) {
        sb.append("SELECT * FROM reports ");
    }

    private void buildWhereClause(StringBuilder sb, String column) {
        sb.append("WHERE ").append(column).append(" = 1 ");  // Tainted!
    }

    private void buildOrderClause(StringBuilder sb, String order) {
        sb.append("ORDER BY ").append(order);  // Tainted!
    }

    // ========================================
    // PATTERN 4: LAMBDA/STREAM EVASION
    // Functional programming hides taint flow
    // ========================================

    public List<Object> lambdaTaintTunnel(Long userId) {
        User user = userRepo.findById(userId).get();
        List<String> filters = Arrays.asList(user.getFilter1(), user.getFilter2());

        // EVASIVE: Taint flows through lambda
        List<String> queries = filters.stream()
            .map(f -> "SELECT * FROM data WHERE " + f)  // Taint preserved!
            .collect(Collectors.toList());

        // 💀 CRITICAL: Each query is tainted
        return queries.stream()
            .map(q -> em.createNativeQuery(q).getResultList())
            .flatMap(List::stream)
            .collect(Collectors.toList());
    }

    public void functionalReduce(Long userId) throws SQLException {
        User user = userRepo.findById(userId).get();
        List<String> conditions = Arrays.asList(
            user.getCondition1(),  // Entity-sourced!
            user.getCondition2(),  // Entity-sourced!
            user.getCondition3()   // Entity-sourced!
        );

        // EVASIVE: reduce() builds tainted query
        String whereClause = conditions.stream()
            .reduce("1=1", (a, b) -> a + " AND " + b);

        String query = "SELECT * FROM sensitive_data WHERE " + whereClause;

        // 💀 CRITICAL: Reduced string is tainted
        connection.createStatement().executeQuery(query);
    }

    // ========================================
    // PATTERN 5: SUPPLIER/CALLABLE EVASION
    // Delayed execution hides the sink
    // ========================================

    public Object supplierEvasion(Long userId) throws Exception {
        User user = userRepo.findById(userId).get();
        String query = user.getDeferredQuery();  // Entity-sourced!

        // EVASIVE: Query execution wrapped in Supplier
        java.util.function.Supplier<ResultSet> querySupplier = () -> {
            try {
                return connection.createStatement().executeQuery(query);
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        };

        // 💀 CRITICAL: Supplier.get() triggers tainted query
        return querySupplier.get();
    }

    public Object callableEvasion(Long configId) throws Exception {
        Config config = configRepo.findById(configId).get();
        String sql = config.getScheduledQuery();  // Entity-sourced!

        // EVASIVE: Callable wrapper
        java.util.concurrent.Callable<List<?>> task = () ->
            em.createNativeQuery(sql).getResultList();

        // 💀 CRITICAL: call() executes tainted SQL
        return task.call();
    }

    // ========================================
    // PATTERN 6: ARRAY/VARARGS EVASION
    // Taint hidden in array elements
    // ========================================

    public void varargsEvasion(Long userId) throws SQLException {
        User user = userRepo.findById(userId).get();

        String[] parts = {
            "SELECT * FROM ",
            user.getTargetTable(),  // Entity-sourced!
            " WHERE id = ",
            user.getTargetId()      // Entity-sourced!
        };

        // EVASIVE: Taint hidden in array
        String query = String.join("", parts);

        // 💀 CRITICAL: Array elements were tainted
        connection.createStatement().executeQuery(query);
    }

    public void arrayIndexEvasion(Long configId) throws SQLException {
        Config config = configRepo.findById(configId).get();

        Object[] queryParts = new Object[3];
        queryParts[0] = "SELECT * FROM ";
        queryParts[1] = config.getTableName();  // Entity-sourced!
        queryParts[2] = " LIMIT 100";

        // EVASIVE: MessageFormat with tainted array element
        String query = java.text.MessageFormat.format("{0}{1}{2}", queryParts);

        // 💀 CRITICAL: queryParts[1] was tainted
        connection.createStatement().executeQuery(query);
    }

    // ========================================
    // PATTERN 7: TERNARY/CONDITIONAL EVASION
    // Taint flows through conditionals
    // ========================================

    public void ternaryEvasion(Long userId, boolean useCustom) throws SQLException {
        User user = userRepo.findById(userId).get();

        // EVASIVE: Taint flows through ternary
        String table = useCustom ? user.getCustomTable() : "default_table";

        String query = "SELECT * FROM " + table;

        // 💀 CRITICAL: 'table' is tainted when useCustom=true
        connection.createStatement().executeQuery(query);
    }

    public void switchEvasion(Long userId, int mode) throws SQLException {
        User user = userRepo.findById(userId).get();
        String column;

        // EVASIVE: Taint flows through switch
        switch (mode) {
            case 1: column = user.getSortColumn1(); break;  // Tainted!
            case 2: column = user.getSortColumn2(); break;  // Tainted!
            default: column = user.getDefaultSort();        // Tainted!
        }

        String query = "SELECT * FROM data ORDER BY " + column;

        // 💀 CRITICAL: All switch branches are tainted
        connection.createStatement().executeQuery(query);
    }

    // ========================================
    // PATTERN 8: OPTIONAL UNWRAP EVASION
    // Optional.orElse() preserves taint
    // ========================================

    public void optionalEvasion(Long userId) throws SQLException {
        Optional<User> optUser = userRepo.findById(userId);

        // EVASIVE: Taint through Optional chain
        String filter = optUser
            .map(User::getSavedFilter)
            .orElse("1=1");

        String query = "SELECT * FROM items WHERE " + filter;

        // 💀 CRITICAL: Optional.map() preserved taint
        connection.createStatement().executeQuery(query);
    }

    // ========================================
    // PATTERN 9: THREAD LOCAL EVASION
    // Taint stored and retrieved later
    // ========================================

    private static final ThreadLocal<String> queryHolder = new ThreadLocal<>();

    public void threadLocalStore(Long userId) {
        User user = userRepo.findById(userId).get();
        // Store tainted data in ThreadLocal
        queryHolder.set(user.getDeferredQuery());
    }

    public void threadLocalExecute() throws SQLException {
        // Retrieve and execute - scanner must track across methods!
        String query = queryHolder.get();

        // 💀 CRITICAL: ThreadLocal contained tainted data
        connection.createStatement().executeQuery(query);
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================

    public List<?> safeParameterized(String userInput) {
        // Safe: Using positional parameter
        return em.createNativeQuery("SELECT * FROM users WHERE id = ?1")
            .setParameter(1, userInput)
            .getResultList();
    }

    public List<?> safePreparedStatement(String userInput) throws SQLException {
        // Safe: PreparedStatement with parameter binding
        PreparedStatement ps = connection.prepareStatement(
            "SELECT * FROM users WHERE id = ?");
        ps.setString(1, userInput);
        return Arrays.asList(ps.executeQuery());
    }
}

// ========================================
// PATTERN 10: SPRING @QUERY ANNOTATION TRAP
// Injection in metadata, not code!
// ========================================

interface UserRepository extends org.springframework.data.jpa.repository.JpaRepository<User, Long> {

    // 💀 CRITICAL: SpEL in native query - sortColumn is injectable!
    @Query(value = "SELECT * FROM users WHERE status = 'ACTIVE' ORDER BY :#{#sortColumn}",
           nativeQuery = true)
    List<User> findActiveUsersSorted(@Param("sortColumn") String sortColumn);

    // 💀 CRITICAL: Direct parameter concatenation in annotation
    @Query(value = "SELECT * FROM users WHERE department = ?1 ORDER BY #{#orderBy}",
           nativeQuery = true)
    List<User> findByDeptOrdered(String dept, @Param("orderBy") String orderBy);

    // 💀 CRITICAL: SpEL with entity property
    @Query("SELECT u FROM User u WHERE u.status = :#{#user.filterStatus}")
    List<User> findByUserFilter(@Param("user") User user);

    // 💀 CRITICAL: Concatenation in JPQL
    @Query("SELECT u FROM User u WHERE u.role = ?1 ORDER BY " + "#{#sortField}")
    List<User> findByRoleSorted(String role, @Param("sortField") String sortField);
}

// ========================================
// PATTERN 11: JPA @NamedNativeQuery TRAP
// ========================================

@Entity
@NamedNativeQuery(
    name = "User.findByDynamicFilter",
    // 💀 CRITICAL: Named query with placeholder for dynamic content
    query = "SELECT * FROM users WHERE :filterClause",
    resultClass = User.class
)
class User {
    @Id private Long id;
    private String savedQuery;
    private String savedFilter;
    private String customId;
    private String filterColumn;
    private String sortPreference;
    private String filter1, filter2;
    private String condition1, condition2, condition3;
    private String deferredQuery;
    private String targetTable, targetId;
    private String customTable;
    private String sortColumn1, sortColumn2, defaultSort;
    private String encodedFilter;
    private String filterStatus;

    // Getters
    public String getSavedQuery() { return savedQuery; }
    public String getSavedFilter() { return savedFilter; }
    public String getCustomId() { return customId; }
    public String getFilterColumn() { return filterColumn; }
    public String getSortPreference() { return sortPreference; }
    public String getFilter1() { return filter1; }
    public String getFilter2() { return filter2; }
    public String getCondition1() { return condition1; }
    public String getCondition2() { return condition2; }
    public String getCondition3() { return condition3; }
    public String getDeferredQuery() { return deferredQuery; }
    public String getTargetTable() { return targetTable; }
    public String getTargetId() { return targetId; }
    public String getCustomTable() { return customTable; }
    public String getSortColumn1() { return sortColumn1; }
    public String getSortColumn2() { return sortColumn2; }
    public String getDefaultSort() { return defaultSort; }
    public String getEncodedFilter() { return encodedFilter; }
    public String getFilterStatus() { return filterStatus; }
}

@Entity
class Config {
    @Id private Long id;
    private String driverClass;
    private String execMethod;
    private String dynamicQuery;
    private String hexFilter;
    private String scheduledQuery;
    private String tableName;

    public String getDriverClass() { return driverClass; }
    public String getExecMethod() { return execMethod; }
    public String getDynamicQuery() { return dynamicQuery; }
    public String getHexFilter() { return hexFilter; }
    public String getScheduledQuery() { return scheduledQuery; }
    public String getTableName() { return tableName; }
}

interface ConfigRepository extends org.springframework.data.jpa.repository.JpaRepository<Config, Long> {}
