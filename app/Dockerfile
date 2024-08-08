FROM ubuntu

# Update package list and install necessary packages
RUN apt update && apt install -y python3-pip python3-venv

# Set the working directory
WORKDIR /app

# Create and activate a virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy the requirements file to the container
COPY requirements.txt .

# Install dependencies within the virtual environment
RUN pip install -r requirements.txt

# Copy the application code to the container
COPY . .

# Command to run the Flask application
CMD ["flask", "run", "--host=0.0.0.0"]