FROM node:18

# Setup a non-root user (Hugging Face Security Requirement)
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# Copy package files first for faster building
COPY --chown=user package*.json ./
RUN npm install

# Copy your app.js and other files
COPY --chown=user . .

# IMPORTANT: Hugging Face uses port 7860
ENV PORT=7860
EXPOSE 7860

CMD [ "node", "app.js" ]