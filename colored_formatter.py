import logging

class ColoredFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[37m",    # Blanc
        "INFO": "\033[32m",     # Vert
        "WARNING": "\033[33m",  # Jaune
        "ERROR": "\033[31m",    # Rouge
        "CRITICAL": "\033[41m", # Fond rouge
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.msg = f"{color}{record.msg}{self.RESET}"
        return super().format(record)
