#hardware.cpu.load.15min	process	host ID	CPU load in the past 15 minutes
#hardware.cpu.load.1min	process	host ID	CPU load in the past 1 minute
#hardware.cpu.load.5min	process	host ID	CPU load in the past 5 minutes
#hardware.cpu.util	%	host ID	cpu usage percentage
#hardware.system_stats.cpu.idle	%	host ID	CPU idle percentage

def getCpuLoad15Min(token, hostID):
    return ''