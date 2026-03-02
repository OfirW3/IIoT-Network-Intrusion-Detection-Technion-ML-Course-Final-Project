FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install core dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    default-jre \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pandas scikit-learn joblib

WORKDIR /app

RUN mkdir -p data/staging data/processing data/csvs data/archive

# Copy the needed files from the host into the container
COPY rf_model.pkl /app/
COPY nids_runner.py /app/
COPY CICFlowMeter/ /app/CICFlowMeter/

RUN chmod +x /app/CICFlowMeter/bin/cfm

# Run the master python script
CMD ["python3", "nids_runner.py"]