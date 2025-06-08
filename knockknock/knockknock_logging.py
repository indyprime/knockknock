from logging import basicConfig, getLogger, INFO
import inspect
from os.path import basename

''' 
This is a convenient way to log information in the same log, with one function: do_log.
'''

#TODO: do filename and module of logger format provide same info as inspect?

# create logger
log_name = 'knockknock'
basicConfig(filename=f'{log_name}.log',
            datefmt='%d %b %Y %H:%M:%S',
            format='%(asctime)s %(message)s',
            level=INFO)
knockknock_logger = getLogger(log_name)


def do_log(message):
    frame = inspect.stack()[1]
    filename = basename(frame.filename)
    function = frame.function
    knockknock_logger.info(f'{filename}:{function}: {message}')


