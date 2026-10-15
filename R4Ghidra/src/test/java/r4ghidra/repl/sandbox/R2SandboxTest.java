package r4ghidra.repl.sandbox;

import java.util.List;

/** Runs without Ghidra or a test framework. */
public final class R2SandboxTest {
  public static void main(String[] args) {
    check(R2Sandbox.parseGrains("none") == 0, "none");
    check(R2Sandbox.parseGrains("all") == R2Sandbox.ALL, "all");
    check(R2Sandbox.parseGrains("file,disk") == (R2Sandbox.FILES | R2Sandbox.DISK), "file alias");
    check(
        R2Sandbox.parseGrains("!disk,!exec") == (R2Sandbox.ALL & ~R2Sandbox.DISK & ~R2Sandbox.EXEC),
        "leading negation");
    check(R2Sandbox.parseGrains("all,none,environ") == R2Sandbox.ENVIRON, "none resets");
    check(R2Sandbox.parseGrains("all,!all,files") == R2Sandbox.FILES, "remove all");
    check(R2Sandbox.parseGrains("  FILES , !disk ") == R2Sandbox.FILES, "spaces and case");
    for (int mask = 0; mask <= R2Sandbox.ALL; mask++) {
      check(R2Sandbox.parseGrains(R2Sandbox.formatGrains(mask)) == mask, "round trip " + mask);
    }
    for (String invalid :
        List.of("", "rw", "unknown", "files,", ",exec", "files,,exec", "!!disk")) {
      rejects(() -> R2Sandbox.parseGrains(invalid));
    }
    R2Sandbox policy = new R2Sandbox();
    check(policy.isRestricted(R2Sandbox.ALL), "default denies host resources");
    policy.setGrains(R2Sandbox.FILES);
    check(!policy.isRestricted(R2Sandbox.FILES), "allow reads");
    check(policy.isRestricted(R2Sandbox.FILES | R2Sandbox.DISK), "write requires both grains");
    rejects(() -> policy.setGrains(128));
    check(policy.getGrains() == R2Sandbox.FILES, "invalid bits preserve policy");
    policy.setEnabled(false);
    check(!policy.isRestricted(R2Sandbox.ALL), "disabled policy");
    policy.setEnabled(true);
    check(policy.isRestricted(R2Sandbox.DISK), "re-enabling preserves grain");
    policy.lock();
    rejects(() -> policy.setEnabled(false));
    rejects(() -> policy.setGrains(R2Sandbox.ALL));
    policy.setGrains(R2Sandbox.NONE);
    rejects(() -> policy.setGrains(R2Sandbox.FILES));
    check(policy.isEnabled() && policy.getGrains() == 0, "locked policy can only narrow");
    System.out.println("Sandbox policy regression tests passed");
  }

  private static void rejects(Runnable action) {
    try {
      action.run();
      throw new AssertionError("Invalid policy accepted");
    } catch (IllegalArgumentException expected) {
      // Expected.
    }
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }
}
