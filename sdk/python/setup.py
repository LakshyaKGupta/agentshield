from setuptools import setup, find_packages

setup(
    name="agentshield",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[],
    author="AgentShield Team",
    author_email="support@agentshield.com",
    description="Runtime security middleware for autonomous AI agents",
    long_description=open("README.md").read() if open("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/LakshyaKGupta/agentshield",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
