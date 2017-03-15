FROM python:2.7
MAINTAINER Eric Young <eric@aceshome.com>

ENV APPDIR /app
RUN mkdir $APPDIR
ENTRYPOINT ["python","/app/deploy-and-configure.py"]

# To get rid of error messages like "debconf: unable to initialize frontend: Dialog":
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

ADD *.py requirements.txt $APPDIR/
RUN cd $APPDIR && pip install -r requirements.txt

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

