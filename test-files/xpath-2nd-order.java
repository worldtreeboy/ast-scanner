/**
 * 2nd-Order XPath Injection Test Cases - "The Hidden Map"
 *
 * XPath injection is harder to detect than SQLi because:
 * 1. No SQL keywords (SELECT, FROM, WHERE) to trigger regex
 * 2. Structural manipulation - breaking out of XML tree logic
 * 3. Blind exfiltration - character-by-character data extraction
 *
 * Attack Payloads:
 * - Breakout: "Engineering' or 1=1 or 'a'='a"
 * - Root access: "/*" or "//*"
 * - Brute force: "user[password='123']"
 * - Boolean blind: "' or substring(//user/password,1,1)='a"
 */
package com.example.xpath;

import javax.xml.xpath.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;

public class XPathInjectionService {

    private UserRepository userRepo;
    private ConfigRepository configRepo;

    // ========================================
    // CRITICAL: Direct Entity Value in XPath
    // ========================================

    public boolean hasAccess(Long userId, String featureId) {
        // Phase 1: Load poisoned department from database
        User user = userRepo.findById(userId).get();
        String dept = user.getDepartment();  // Entity-sourced!

        // Phase 2: Build ACL XPath query
        Document doc = loadXml("permissions.xml");
        XPath xpath = XPathFactory.newInstance().newXPath();

        // CRITICAL VULN: String concatenation in evaluate()
        // Intended: //dept[@name='Engineering']/feature[@id='AdminPanel']
        // Injected: //dept[@name='Engineering' or 1=1 or 'a'='a']/feature[@id='AdminPanel']
        String expression = "//dept[@name='" + dept + "']/feature[@id='" + featureId + "']";

        try {
            NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);
            return nodes.getLength() > 0;
        } catch (XPathExpressionException e) {
            return false;
        }
    }

    // ========================================
    // CRITICAL: Config-Sourced XPath Path
    // ========================================

    public Object getConfiguredData(Long configId, Document doc) {
        // Phase 1: Fetch XPath expression from database config
        Config config = configRepo.findById(configId).get();
        String storedPath = config.getXpathFilter();  // Entity-sourced!

        XPath xpath = XPathFactory.newInstance().newXPath();

        // CRITICAL VULN: Entire path from DB
        // If storedPath = "/*" -> Returns entire XML document
        // If storedPath = "//user[password='admin']" -> Brute force passwords
        try {
            return xpath.evaluate("/root/" + storedPath, doc, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    // ========================================
    // CRITICAL: XPathExpression.compile() Sink
    // ========================================

    public NodeList searchByStoredFilter(Long userId, Document doc) {
        User user = userRepo.findById(userId).get();
        String filter = user.getSavedFilter();  // Entity-sourced!

        XPath xpath = XPathFactory.newInstance().newXPath();

        // CRITICAL VULN: compile() with entity value
        // Attacker stores: "//user" to enumerate all users
        try {
            XPathExpression expr = xpath.compile("//items/item[" + filter + "]");
            return (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    // ========================================
    // CRITICAL: String.format XPath Pattern
    // ========================================

    public Node findUserNode(Long userId, Document doc) {
        User user = userRepo.findById(userId).get();
        String username = user.getDisplayName();  // Entity-sourced!

        XPath xpath = XPathFactory.newInstance().newXPath();

        // CRITICAL VULN: String.format doesn't escape XPath
        // Payload in username: "admin' or '1'='1"
        String expression = String.format("//users/user[@name='%s']", username);

        try {
            return (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    // ========================================
    // CRITICAL: Deep Entity Chain
    // ========================================

    public NodeList deepEntityXPath(Long userId, Document doc) {
        // Deep entity access chain
        User user = userRepo.findById(userId).get();
        Profile profile = user.getProfile();
        Settings settings = profile.getSettings();
        String filterPath = settings.getXmlFilterPath();  // Deep entity chain!

        XPath xpath = XPathFactory.newInstance().newXPath();

        // CRITICAL VULN: Entity chain flowing to XPath
        try {
            return (NodeList) xpath.evaluate(filterPath, doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    // ========================================
    // CRITICAL: StringBuilder XPath Building
    // ========================================

    public NodeList buildXPathQuery(Long userId, Document doc) {
        User user = userRepo.findById(userId).get();
        String category = user.getPreferredCategory();  // Entity-sourced!
        String status = user.getFilterStatus();  // Entity-sourced!

        StringBuilder xpathBuilder = new StringBuilder();
        xpathBuilder.append("//products/product[");
        xpathBuilder.append("category='" + category + "'");  // VULN
        xpathBuilder.append(" and status='" + status + "'");  // VULN
        xpathBuilder.append("]");

        XPath xpath = XPathFactory.newInstance().newXPath();

        try {
            return (NodeList) xpath.evaluate(xpathBuilder.toString(), doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    // ========================================
    // CRITICAL: MessageFormat XPath (Rare)
    // ========================================

    public Node messageFormatXPath(Long configId, Document doc) {
        Config config = configRepo.findById(configId).get();
        String fieldName = config.getSearchField();  // Entity-sourced!

        XPath xpath = XPathFactory.newInstance().newXPath();

        // CRITICAL VULN: MessageFormat XPath
        String expression = java.text.MessageFormat.format(
            "//record[@{0}=''value'']", fieldName
        );

        try {
            return (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    // ========================================
    // CRITICAL: Blind XPath Exfiltration
    // ========================================

    public boolean blindXPathProbe(Long userId, Document doc) {
        // This pattern enables character-by-character password extraction
        User user = userRepo.findById(userId).get();
        String probeChar = user.getProbeValue();  // Entity-sourced!

        XPath xpath = XPathFactory.newInstance().newXPath();

        // CRITICAL: Blind XPath injection
        // Payload: "a" -> "' or substring(//admin/password,1,1)='a"
        // Response time or boolean difference reveals each character
        String expression = "//users/user[password='" + probeChar + "']";

        try {
            NodeList nodes = (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);
            return nodes.getLength() > 0;
        } catch (XPathExpressionException e) {
            return false;
        }
    }

    // ========================================
    // HIGH: DOM Document XPath (Alternative API)
    // ========================================

    public NodeList domXPathQuery(Long userId) throws Exception {
        User user = userRepo.findById(userId).get();
        String selector = user.getXmlSelector();  // Entity-sourced!

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Document doc = factory.newDocumentBuilder().parse("data.xml");

        // HIGH VULN: getElementsByTagName with entity value
        // Less dangerous but still exploitable for enumeration
        return doc.getElementsByTagName(selector);
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================

    public NodeList safeHardcodedXPath(Document doc) {
        XPath xpath = XPathFactory.newInstance().newXPath();

        // Safe: Hardcoded XPath expression
        try {
            return (NodeList) xpath.evaluate("//users/user[@active='true']", doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    public NodeList safeWhitelistValidation(Long userId, Document doc) {
        User user = userRepo.findById(userId).get();
        String category = user.getCategory();

        // Safe: Whitelist validation
        java.util.List<String> allowedCategories = java.util.List.of("books", "electronics", "clothing");
        if (!allowedCategories.contains(category)) {
            category = "books";  // Default to safe value
        }

        XPath xpath = XPathFactory.newInstance().newXPath();

        // Safe after validation
        try {
            return (NodeList) xpath.evaluate("//products/product[@category='" + category + "']", doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    public NodeList safeEscapedValue(Long userId, Document doc) {
        User user = userRepo.findById(userId).get();
        String searchTerm = user.getSearchTerm();

        // Safe: Proper escaping (hypothetical escape function)
        String escapedTerm = escapeXPath(searchTerm);

        XPath xpath = XPathFactory.newInstance().newXPath();
        try {
            return (NodeList) xpath.evaluate("//items/item[name='" + escapedTerm + "']", doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    private String escapeXPath(String input) {
        // Proper XPath escaping implementation
        return input.replace("'", "&apos;").replace("\"", "&quot;");
    }

    private Document loadXml(String filename) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            return factory.newDocumentBuilder().parse(filename);
        } catch (Exception e) {
            return null;
        }
    }
}

// Entity classes
class User {
    private Long id;
    private String department;
    private String savedFilter;
    private String displayName;
    private Profile profile;
    private String preferredCategory;
    private String filterStatus;
    private String probeValue;
    private String xmlSelector;
    private String category;
    private String searchTerm;

    public String getDepartment() { return department; }
    public String getSavedFilter() { return savedFilter; }
    public String getDisplayName() { return displayName; }
    public Profile getProfile() { return profile; }
    public String getPreferredCategory() { return preferredCategory; }
    public String getFilterStatus() { return filterStatus; }
    public String getProbeValue() { return probeValue; }
    public String getXmlSelector() { return xmlSelector; }
    public String getCategory() { return category; }
    public String getSearchTerm() { return searchTerm; }
}

class Profile {
    private Settings settings;
    public Settings getSettings() { return settings; }
}

class Settings {
    private String xmlFilterPath;
    public String getXmlFilterPath() { return xmlFilterPath; }
}

class Config {
    private Long id;
    private String xpathFilter;
    private String searchField;

    public String getXpathFilter() { return xpathFilter; }
    public String getSearchField() { return searchField; }
}

interface UserRepository {
    java.util.Optional<User> findById(Long id);
}

interface ConfigRepository {
    java.util.Optional<Config> findById(Long id);
}
