from setuptools import setup

setup(
    name="firegun",
    version="0.8.0",
    py_modules=["firegun"],
    install_requires=[
        "httpx",
        "requests",
        "firebase-admin",
        "google-cloud-firestore",
    ],
    entry_points={
        "console_scripts": [
            "firegun = firegun:main",
        ],
    },
)

