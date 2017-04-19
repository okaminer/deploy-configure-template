FROM python:2.7
MAINTAINER Eric Young <eric.young@emc.com>

ENV APPDIR /app
RUN mkdir $APPDIR
ENTRYPOINT ["python","/app/deploy-and-configure.py"]

# To get rid of error messages like "debconf: unable to initialize frontend: Dialog":
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# define the pyhton requirements and install them
ADD requirements.txt $APPDIR/
RUN cd $APPDIR && pip install -r requirements.txt
# add the python modules
ADD *.py $APPDIR/

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
