module Net; module SSH; module Connection
      
  # Terminal opcodes, for use when opening pty's.
  module Term

    TTY_OP_END = 0
    VINTR = 1
    VQUIT = 2
    VERASE = 3
    VKILL = 4
    VEOF = 5
    VEOL = 6
    VEOL2 = 7
    VSTART = 8
    VSTOP = 9
    VSUSP = 10
    VDSUSP = 11
    VREPRINT = 12
    VWERASE = 13
    VLNEXT = 14
    VFLUSH = 15
    VSWITCH = 16
    VSTATUS = 17
    VDISCARD = 18

    IGNPAR = 30
    PARMRK = 31
    INPCK = 32
    ISTRIP = 33
    INCLR = 34
    IGNCR = 35
    ICRNL = 36
    IUCLC = 37
    IXON = 38
    IXANY = 39
    IXOFF = 40
    IMAXBEL = 41

    ISIG = 50
    ICANON = 51
    XCASE = 52
    ECHO = 53
    ECHOE = 54
    ECHOK = 55
    ECHONL = 56
    NOFLSH = 57
    TOSTOP= 58
    IEXTEN = 59
    ECHOCTL = 60
    ECHOKE = 61
    PENDIN = 62

    OPOST = 70
    OLCUC = 71
    ONLCR = 72
    OCRNL = 73
    ONOCR = 74
    ONLRET = 75

    CS7 = 90
    CS8 = 91
    PARENB = 92
    PARODD = 93

    TTY_OP_ISPEED = 128
    TTY_OP_OSPEED = 129

  end

end; end; end
