## coreplugin.py - Core PyLink plugin

import utils
from log import log
import world

# Handle KILLs sent to the PyLink client and respawn
def handle_kill(irc, source, command, args):
    if args['target'] == irc.pseudoclient.uid:
        irc.spawnMain()
utils.add_hook(handle_kill, 'KILL')

# Handle KICKs to the PyLink client, rejoining the channels
def handle_kick(irc, source, command, args):
    kicked = args['target']
    channel = args['channel']
    if kicked == irc.pseudoclient.uid:
        irc.proto.joinClient(irc.pseudoclient.uid, channel)
utils.add_hook(handle_kick, 'KICK')

# Handle commands sent to the PyLink client (PRIVMSG)
def handle_commands(irc, source, command, args):
    if args['target'] == irc.pseudoclient.uid:
        text = args['text'].strip()
        cmd_args = text.split(' ')
        cmd = cmd_args[0].lower()
        cmd_args = cmd_args[1:]
        if cmd not in world.bot_commands:
            irc.msg(source, 'Error: Unknown command %r.' % cmd)
            return
        log.info('(%s) Calling command %r for %s', irc.name, cmd, utils.getHostmask(irc, source))
        for func in world.bot_commands[cmd]:
            try:
                func(irc, source, cmd_args)
            except utils.NotAuthenticatedError:
                irc.msg(source, 'Error: You are not authorized to perform this operation.')
            except Exception as e:
                log.exception('Unhandled exception caught in command %r', cmd)
                irc.msg(source, 'Uncaught exception in command %r: %s: %s' % (cmd, type(e).__name__, str(e)))
utils.add_hook(handle_commands, 'PRIVMSG')

# Handle WHOIS queries, for IRCds that send them across servers (charybdis, UnrealIRCd; NOT InspIRCd).
def handle_whois(irc, source, command, args):
    target = args['target']
    user = irc.users.get(target)
    if user is None:
        log.warning('(%s) Got a WHOIS request for %r from %r, but the target '
                    'doesn\'t exist in irc.users!', irc.name, target, source)
        return
    f = irc.proto.numericServer
    server = utils.clientToServer(irc, target) or irc.sid
    nick = user.nick
    sourceisOper = ('o', None) in irc.users[source].modes
    # https://www.alien.net.au/irc/irc2numerics.html
    # 311: sends nick!user@host information
    f(server, 311, source, "%s %s %s * :%s" % (nick, user.ident, user.host, user.realname))
    # 319: RPL_WHOISCHANNELS, shows channel list
    public_chans = []
    for chan in user.channels:
        # Here, we'll want to hide secret/private channels from non-opers
        # who are not in them.
        c = irc.channels[chan]
        if ((irc.cmodes.get('secret'), None) in c.modes or \
            (irc.cmodes.get('private'), None) in c.modes) \
            and not (sourceisOper or source in c.users):
                continue
        # Show prefix modes like a regular IRCd does.
        for prefixmode, prefixchar in irc.prefixmodes.items():
            modename = [mname for mname, char in irc.cmodes.items() if char == prefixmode]
            if modename and target in c.prefixmodes[modename[0]+'s']:
                chan = prefixchar + chan
        public_chans.append(chan)
    if public_chans:
        f(server, 319, source, '%s :%s' % (nick, ' '.join(public_chans)))
    # 312: sends the server the target is on, and its server description.
    f(server, 312, source, "%s %s :%s" % (nick, irc.servers[server].name,
      irc.servers[server].desc))
    # 313: sends a string denoting the target's operator privilege,
    # only if they have umode +o.
    if ('o', None) in user.modes:
        if hasattr(user, 'opertype'):
            opertype = user.opertype
        else:
            opertype = "IRC Operator"
        # Let's be gramatically correct.
        n = 'n' if opertype[0].lower() in 'aeiou' else ''
        f(server, 313, source, "%s :is a%s %s" % (nick, n, opertype))
    # 379: RPL_WHOISMODES, used by UnrealIRCd and InspIRCd.
    # Only show this to opers!
    if sourceisOper:
        f(server, 378, source, "%s :is connecting from %s@%s %s" % (nick, user.ident, user.realhost, user.ip))
        f(server, 379, source, '%s :is using modes %s' % (nick, utils.joinModes(user.modes)))
    # 317: shows idle and signon time. However, we don't track the user's real
    # idle time, so we simply return 0.
    # <- 317 GL GL 15 1437632859 :seconds idle, signon time
    f(server, 317, source, "%s 0 %s :seconds idle, signon time" % (nick, user.ts))
    for func in world.whois_handlers:
    # Iterate over custom plugin WHOIS handlers. They return a tuple
    # or list with two arguments: the numeric, and the text to send.
        try:
            res = func(irc, target)
            if res:
                num, text = res
                f(server, num, source, text)
        except Exception as e:
            # Again, we wouldn't want this to crash our service, in case
            # something goes wrong!
            log.exception('(%s) Error caught in WHOIS handler: %s', irc.name, e)
    # 318: End of WHOIS.
    f(server, 318, source, "%s :End of /WHOIS list" % nick)
utils.add_hook(handle_whois, 'WHOIS')
