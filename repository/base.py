from abc import ABC, abstractmethod

class BaseRepository(ABC):
    """Defines the interface (contract) for all data storage repositories."""

    @abstractmethod
    def get_all_policies(self): pass

    @abstractmethod
    def get_policy_by_id(self, policy_id): pass

    @abstractmethod
    def save_new_policy(self, policy_data, username): pass

    @abstractmethod
    def update_policy(self, policy_id, updated_data, username): pass

    @abstractmethod
    def get_all_users(self): pass

    @abstractmethod
    def get_user_by_id(self, user_id): pass

    @abstractmethod
    def get_user_by_username(self, username): pass

    @abstractmethod
    def save_user(self, user_data): pass

    @abstractmethod
    def delete_user(self, user_id): pass

    @abstractmethod
    def get_all_categories(self): pass

    @abstractmethod
    def get_category_by_name(self, category_name): pass

    @abstractmethod
    def save_all_categories(self, categories_list): pass

    # ... Add abstract methods for all other data functions (groups, operators, etc.)
