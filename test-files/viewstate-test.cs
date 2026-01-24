using System;
using System.IO;
using System.Web.UI;
using System.Web;

public partial class LegacyHandler : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        // SOURCE: Taking data directly from a hidden form field (tainted)
        string rawViewState = Request.Form["__CUSTOM_VIEWSTATE"];

        if (!string.IsNullOrEmpty(rawViewState))
        {
            ProcessViewState(rawViewState);
        }
    }

    private void ProcessViewState(string base64Data)
    {
        try
        {
            // Conversion of tainted string to byte array
            byte[] data = Convert.FromBase64String(base64Data);

            using (MemoryStream ms = new MemoryStream(data))
            {
                // SINK: LosFormatter (Object State Formatter)
                // This is the "Ghost" in the machine.
                // It is designed to deserialize ViewState objects.
                // Without MachineKey validation, this leads to RCE (Remote Code Execution).
                LosFormatter formatter = new LosFormatter();

                // If an attacker uses a tool like 'ysoserial.net',
                // this Deserialize call will execute their payload.
                object sessionData = formatter.Deserialize(ms);

                lblStatus.Text = "ViewState Processed Successfully";
            }
        }
        catch (Exception ex)
        {
            // Common mistake: leaking error details
            Response.Write("Error: " + ex.Message);
        }
    }

    // ObjectStateFormatter is equally dangerous
    private void ProcessWithObjectState(string data)
    {
        byte[] bytes = Convert.FromBase64String(data);
        ObjectStateFormatter osf = new ObjectStateFormatter();
        object result = osf.Deserialize(new MemoryStream(bytes));
    }
}
