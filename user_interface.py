class UIManager:
    def __init__(self):
        pass

    def display_message(self, message):
        print(message)

class UserConfirmation:
    def __init__(self):
        pass

    def get_confirmation(self, prompt):
        response = input(prompt)
        return response.lower() == 'y'
