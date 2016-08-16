import os, sys

# Standalone code ======================================================================================================
def createDevice():
    from AtumsoftGeneric import AtumsoftGeneric
    tunTap = AtumsoftGeneric(isVirtual=False, iface='eth0') # physical on ethernet port

    #tunTap = AtumsoftGeneric()
    #tunTap.createTunTapAdapter(name='mytun', ipAddress='192.168.2.101') # virtual for testing
    #tunTap.openTunTap()

    tunTap.startCapture()


# Helper functions to check for admin privileges on run ================================================================
def checkForAdmin():
    try:
        is_admin = os.getuid() == 0
        if not is_admin:
            print "Script not started as root. Running sudo.."
            args = ['sudo', sys.executable] + sys.argv + [os.environ]
            # the next line replaces the currently-running process with the sudo
            os.execlpe('gksudo', *args)

    except AttributeError:
        print 'this part of the code must be run on a Unix system only'


if __name__ == '__main__':
    checkForAdmin()
    # thread.start_new_thread(run(), tuple()) # FIXME: sending tuple() is a hacky way to overcome start_new_threads requirement on sending args
    createDevice()
