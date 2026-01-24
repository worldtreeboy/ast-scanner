using System;
using System.Xml;
using System.IO;

public class DataIngestor {
    // LEVEL 1: The XXE Trap
    // Developers often forget that XML Parsers are "Too Helpful" by default.
    public void ProcessUserXml(string xmlInput) {
        XmlDocument xmlDoc = new XmlDocument();
        
        // THE MISTAKE: Allowing DTD processing and External Entities.
        // Attack: Sending a DTD that reads C:\windows\win.ini
        xmlDoc.XmlResolver = new XmlUrlResolver(); 
        xmlDoc.LoadXml(xmlInput); 
        
        Console.WriteLine(xmlDoc.InnerText);
    }

    // LEVEL 2: The "Tainted Property" Mystery
    // The taint is set in one method but executed in another.
    public class GhostTask {
        public string Command { get; set; }
        
        public void Execute() {
            // THE SINK: Hidden in a simple class method
            System.Diagnostics.Process.Start("cmd.exe", "/c " + Command);
        }
    }

    public void ScheduleTask(string userInput) {
        GhostTask task = new GhostTask();
        task.Command = userInput; // The taint enters the object property
        task.Execute();           // The sink is triggered
    }
}
