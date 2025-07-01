package r4ghidra;

public class R2P8Cmd extends R2CmdHandler {
	
	public R2P8Cmd(int i) {
		cmdPos=i;
	}

	@Override
	public boolean canHandle(char cmdChar) {
		if (cmdChar == '8') return true;
		return false;
	}

    private String cmdPrint8(String arg) {
        int len = Integer.parseInt(arg);
        if (len < 1) {
          len = R4GhidraState.blockSize;
        }
        StringBuffer sb = new StringBuffer();
        try {
          byte[] bytes = R4GhidraState.api.getBytes(R4GhidraState.r2Seek, len);
          for (int i = 0; i < bytes.length; i++) {
            String b = Integer.toHexString(0x100 | (int) (bytes[i] & 0xff)).substring(1);
            sb.append(b);
          }
        } catch (Exception e) {
          sb.append(e.toString());
        }
        return sb.toString() + "\n";
      }


	@Override
	public String handle(String cmd) {
		String[] parts = cmd.split(" ");
		String arg = "-1";
		if (parts.length > 1) {
			arg = parts[1];
		}
		return cmdPrint8(arg);
	}

}
