"""Security rules registry and auto-discovery system."""

from typing import List, Type
from .base import Rule, Finding, Severity, Evidence

__all__ = ['Rule', 'Finding', 'Severity', 'Evidence', 'register_rule', 'get_all_rules']

# Global registry for rule classes
_RULE_REGISTRY: List[Type[Rule]] = []


def register_rule(rule_class: Type[Rule]):
    """Decorator to register a rule class for auto-discovery.

    Usage:
        @register_rule
        class MyRule(Rule):
            ...

    Args:
        rule_class: The Rule subclass to register

    Returns:
        The same rule class (allows decorator usage)
    """
    if not issubclass(rule_class, Rule):
        raise TypeError(f"{rule_class.__name__} must inherit from Rule")

    _RULE_REGISTRY.append(rule_class)
    return rule_class


def get_all_rules() -> List[Rule]:
    """Get instances of all registered rules.

    Returns:
        List of instantiated Rule objects ready to execute

    Note:
        Rules must be imported before this function is called.
        The scanner module imports all rule modules to trigger registration.
    """
    return [rule_class() for rule_class in _RULE_REGISTRY]


def get_rules_by_category(category: str) -> List[Rule]:
    """Get rules filtered by category (DOCKER, FASTAPI, GENERAL).

    Args:
        category: Category prefix (e.g., 'DOCKER', 'FASTAPI', 'GENERAL')

    Returns:
        List of Rule instances matching the category
    """
    all_rules = get_all_rules()
    return [rule for rule in all_rules if rule.id.startswith(category)]


def get_rule_count() -> int:
    """Get total number of registered rules.

    Returns:
        Number of rules in the registry
    """
    return len(_RULE_REGISTRY)
