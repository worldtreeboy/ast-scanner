using System.Xml.Xsl;

public class TransformError {
    public void Transform(string xmlPath, string xsltPath) {
        // MISTAKE: Enabling document() function in XSLT
        XslCompiledTransform transformer = new XslCompiledTransform();
        XsltSettings settings = new XsltSettings(true, false);

        transformer.Load(xsltPath, settings, new XmlUrlResolver());
        transformer.Transform(xmlPath, "output.html");
    }

    // Even worse: TrustedXslt enables everything
    public void DangerousTransform(string xmlPath, string xsltPath) {
        XslCompiledTransform transformer = new XslCompiledTransform();
        transformer.Load(xsltPath, XsltSettings.TrustedXslt, new XmlUrlResolver());
        transformer.Transform(xmlPath, "output.html");
    }

    // Resolver only - still risky
    public void ResolverOnly(string xmlPath, string xsltPath) {
        XslCompiledTransform transformer = new XslCompiledTransform();
        transformer.Load(xsltPath, null, new XmlUrlResolver());
        transformer.Transform(xmlPath, "output.html");
    }
}
