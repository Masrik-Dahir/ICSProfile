import os


def get_parent_directory(path):
    """
    Returns the parent directory of the given path.

    Args:
        path (str): The input file or directory path.

    Returns:
        str: The parent directory of the given path.
        :param path:
        :return:
    """
    return os.path.dirname(path)