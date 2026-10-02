import gymnasium as gym
from collections import deque
import numpy as np

class RepetitionGuardWrapper(gym.Wrapper):
    """
    A wrapper to penalize the agent for repeating the same action multiple times in a row.
    This is useful in live testing to prevent the agent from getting stuck.
    """
    def __init__(self, env, max_repetitions=3, penalty=-25):
        """
        Initializes the wrapper.

        Args:
            env: The environment to wrap.
            max_repetitions (int): The number of consecutive repetitions to trigger the penalty.
            penalty (int): The negative reward to apply when the agent is stuck.
        """
        if not isinstance(env, gym.Env):
            raise TypeError(f"Expected gym.Env, got {type(env)}")
        self.env = env
        self.max_repetitions = max_repetitions
        self.penalty = penalty
        self.action_history = deque(maxlen=self.max_repetitions)

    def step(self, action):
        """
        Overrides the step method to add a penalty for repetitive actions.
        """
        # Check if the current action would be a repetition
        is_repetitive = False
        if len(self.action_history) == self.max_repetitions:
            if all(a == action for a in self.action_history):
                is_repetitive = True

        self.action_history.append(action)

        # Get the original observation, reward, terminated, truncated, info
        observation, reward, terminated, truncated, info = self.env.step(action)

        # Apply penalty if the action is repetitive
        if is_repetitive:
            reward += self.penalty
            info['repetition_penalty'] = self.penalty
            print(f"Repetition Guard: Applied penalty of {self.penalty} for repeating action {action}.")
            # To further break loops, we might consider forcing a "done" state,
            # but for now, a penalty is less disruptive.
            # terminated = True 

        return observation, reward, terminated, truncated, info

    def reset(self, **kwargs):
        """
        Resets the environment and clears the action history.
        """
        self.action_history.clear()
        # The line below was causing an error with the new gymnasium API.
        # It should call the parent's reset method and return its result.
        return self.env.reset(**kwargs)
        
    # Forward attribute access to the wrapped env
    def __getattr__(self, name):
        """
        Forward attribute access to the wrapped environment.
        This ensures that attributes like current_state are accessible.
        """
        if name.startswith('_'):
            raise AttributeError(f"accessing private attribute '{name}' is prohibited")
        return getattr(self.env, name)

def apply_repetition_guard(env, **kwargs):
    """
    Factory function to apply the RepetitionGuardWrapper to an environment.
    """
    return RepetitionGuardWrapper(env, **kwargs)