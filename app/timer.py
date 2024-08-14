# Timer Class
TOTAL_SECONDS = 60 * 15

class Timer:
    def __init__(self, current_time):
        self.current_time = current_time

    def decrement(self):
        if self.current_time > 0:
            self.current_time = self.current_time - 1
        return self.current_time
    
    # Function to format seconds into minutes and seconds
    def format_time(self):
        minutes, seconds = divmod(self.current_time, 60)
        return f"{minutes:02}:{seconds:02}"