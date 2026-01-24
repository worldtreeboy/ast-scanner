public class Bomb {
    private string _cmd;
    public Bomb(string cmd) { _cmd = cmd; }

    // This runs automatically when the program finishes or cleans up
    ~Bomb() {
        System.Diagnostics.Process.Start("cmd.exe", "/c " + _cmd);
    }
}
