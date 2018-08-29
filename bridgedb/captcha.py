# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Aaron Gibson   0x2C4B239DD876C9F6 <aagbsn@torproject.org>
#           Nick Mathewson 0x21194EBB165733EA <nickm@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2017, The Tor Project, Inc.
#             (c) 2007-2017, all entities within the AUTHORS file
#             (c) 2014-2017, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""This module implements various methods for obtaining or creating CAPTCHAs.

.. inheritance-diagram:: CaptchaExpired CaptchaKeyError GimpCaptchaError Captcha ReCaptcha GimpCaptcha
    :parts: 1

**Module Overview:**

::

  bridgedb.captcha
   |- CaptchaExpired - Raised if a solution is given for a stale CAPTCHA.
   |- CaptchaKeyError - Raised if a CAPTCHA system's keys are invalid/missing.
   |- GimpCaptchaError - Raised when a Gimp CAPTCHA can't be retrieved.
   |
   \_ ICaptcha - Zope Interface specification for a generic CAPTCHA.
        |
      Captcha - Generic base class implementation for obtaining a CAPTCHA.
      |  |- image - The CAPTCHA image.
      |  |- audio - The CAPTCHA audio.
      |  |- challenge - A unique string associated with this CAPTCHA media.
      |  |- publicKey - The public key for this CAPTCHA system.
      |  |- secretKey - The secret key for this CAPTCHA system.
      |   \_ get() - Get a new pair of CAPTCHA media and challenge strings.
      |
      |- ReCaptcha - Obtain reCaptcha images and challenge strings.
      |   \_ get() - Request an image and challenge from a reCaptcha API server.
      |
      \_ GimpCaptcha - Class for obtaining a CAPTCHA from a local cache.
          |- hmacKey - A client-specific key for HMAC generation.
          |- cacheImageDir - The path to the local CAPTCHA image cache directory.
          |- cacheAudioDIr - The path to the local CAPTCHA audio cache directory.
          |- sched - A class for timing out CAPTCHAs after an interval.
          \_ get() - Get CAPTCHA image, audio from the cache and create a challenge.

..

There are two types of CAPTCHAs which BridgeDB knows how to serve: those
obtained by from a reCaptcha_ API server with
:class:`~bridgedb.captcha.Raptcha`, and those which have been generated with
gimp-captcha_ and then cached locally.

.. _reCaptcha : https://code.google.com/p/recaptcha/
.. _gimp-captcha: https://github.com/isislovecruft/gimp-captcha
"""

from base64 import urlsafe_b64encode
from base64 import urlsafe_b64decode

import logging
import random
import os
import time
import urllib2

from BeautifulSoup import BeautifulSoup

from zope.interface import Interface, Attribute, implements

from bridgedb import crypto
from bridgedb import schedule
from bridgedb.txrecaptcha import API_SSL_SERVER


class CaptchaExpired(ValueError):
    """Raised when a client's CAPTCHA is too stale."""

class CaptchaKeyError(Exception):
    """Raised if a CAPTCHA system's keys are invalid or missing."""

class GimpCaptchaError(Exception):
    """General exception raised when a Gimp CAPTCHA cannot be retrieved."""


class ICaptcha(Interface):
    """Interface specification for CAPTCHAs."""

    image = Attribute(
        "A string containing the contents of a CAPTCHA image file.")
    audio = Attribute(
        "A string containing the contents of a CAPTCHA audio file.")
    challenge = Attribute(
        "A unique string associated with the dispursal of this CAPTCHA.")
    publicKey = Attribute(
        "A public key used for encrypting CAPTCHA challenge strings.")
    secretKey = Attribute(
        "A private key used for decrypting challenge strings during CAPTCHA"
        "solution verification.")

    def get():
        """Retrieve a new CAPTCHA image."""


class Captcha(object):
    """A generic CAPTCHA base class.

    :vartype image: str
    :ivar image: The CAPTCHA image.
    :vartype audio: str
    :ivar audio: The CAPTCHA audio.
    :vartype challenge: str
    :ivar challenge: A challenge string which should permit checking of
        the client's CAPTCHA solution in some manner. In stateless protocols
        such as HTTP, this should be passed along to the client with the
        CAPTCHA media.
    :vartype publicKey: str
    :ivar publicKey: A public key used for encrypting CAPTCHA challenge strings.
    :vartype secretKey: str
    :ivar secretKey: A private key used for decrypting challenge strings during
        CAPTCHA solution verification.
    """
    implements(ICaptcha)

    def __init__(self, publicKey=None, secretKey=None):
        """Obtain a new CAPTCHA for a client."""
        self.image = None
        self.audio = None
        self.challenge = None
        self.publicKey = publicKey
        self.secretKey = secretKey

    def get(self):
        """Retrieve new CAPTCHA media and its associated challenge string.

        The image and challenge will be stored as
        :attr:`image <bridgedb.captcha.Captcha.image>`,
        :attr:`image <bridgedb.captcha.Captcha.audio>` and
        :attr:`challenge <bridgedb.captcha.Captcha.challenge>`, respectively.
        """
        self.image = None
        self.audio = None
        self.challenge = None


class ReCaptcha(Captcha):
    """A CAPTCHA obtained from a remote reCaptcha_ API server.

    :vartype image: str
    :ivar image: The CAPTCHA image.
    :vartype audio: str
    :ivar audio: The CAPTCHA audio.
    :vartype challenge: str
    :ivar challenge: The ``'recaptcha_challenge_response'`` HTTP form
        field to pass to the client, along with the CAPTCHA image. See
        :doc:`BridgeDB's captcha.html <templates/captcha.html>` Mako_ template
        for an example usage.
    :vartype publicKey: str
    :ivar publicKey: The public reCaptcha API key.
    :vartype secretKey: str
    :ivar secretKey: The private reCaptcha API key.

    .. _reCaptcha: https://code.google.com/p/recaptcha/
    .. _Mako: http://docs.makotemplates.org/en/latest/syntax.html#page
    """

    def __init__(self, publicKey=None, secretKey=None):
        """Create a new ReCaptcha CAPTCHA.

        :param str publicKey: The public reCaptcha API key.
        :param str secretKey: The private reCaptcha API key.
        """
        super(ReCaptcha, self).__init__(publicKey=publicKey,
                                        secretKey=secretKey)

    def get(self):
        """Retrieve a CAPTCHA from the reCaptcha API server.

        This simply requests a new CAPTCHA from
        ``recaptcha.client.captcha.API_SSL_SERVER`` and parses the returned
        HTML to extract the CAPTCHA image and challenge string. The image is
        stored at ``ReCaptcha.image`` and the challenge string at
        ``ReCaptcha.challenge``. An empty string is stored in ``ReCaptcha.audio``;
        audio CAPTCHAs are not implemented.

        :raises CaptchaKeyError: If either the :attr:`publicKey` or
            :attr:`secretKey` are missing.
        :raises HTTPError: If the server returned any HTTP error status code.
        """
        if not self.publicKey or not self.secretKey:
            raise CaptchaKeyError('You must supply recaptcha API keys')

        urlbase = API_SSL_SERVER
        form = "/noscript?k=%s" % self.publicKey

        # Extract and store image from recaptcha
        html = urllib2.urlopen(urlbase + form).read()
        # FIXME: The remaining lines currently cannot be reliably unit tested:
        soup = BeautifulSoup(html)                           # pragma: no cover
        imgurl = urlbase + "/" +  soup.find('img')['src']    # pragma: no cover
        cField = soup.find(                                  # pragma: no cover
            'input', {'name': 'recaptcha_challenge_field'})  # pragma: no cover
        self.challenge = str(cField['value'])                # pragma: no cover
        self.image = urllib2.urlopen(imgurl).read()          # pragma: no cover

        # TODO: Audio isn't implemented for ReCaptcha.
        # In other places, I've stuck an empty string as a response for the
        # ReCaptcha case; will stick it here aswell.
        self.audio = ''


class GimpCaptcha(Captcha):
    """A locally cached CAPTCHA image/audio which was created with
    a utility such as gimp-captcha_.

    :vartype publicKey: str
    :ivar publicKey: A PKCS#1 OAEP-padded, public RSA key. This is used to
        hide the correct CAPTCHA solution within the
        ``captcha_challenge_field`` HTML form field. That form field is given
        to the a client along with the :attr:`image` during the initial
        CAPTCHA request, and the client *should* give it back to us later
        during the CAPTCHA solution verification step.
    :vartype secretKey: str
    :ivar secretKey: A PKCS#1 OAEP-padded, private RSA key, used for
        verifying the client's solution to the CAPTCHA.
    :vartype hmacKey: bytes
    :ivar hmacKey: A client-specific HMAC secret key.
    :vartype cacheImageDir: str
    :ivar cacheImageDir: The local directory which pre-generated CAPTCHA images
        have been stored in. This can be set via the ``GIMP_CAPTCHA_DIR``
        setting in the config file.
    :vartype cacheAudioDir: str
    :ivar cacheAudioDir: The local directory which pre-generated CAPTCHA audio
        has been stored in. This can be set via the ``GIMP_CAPTCHA_AUDIO_DIR``
        setting in the config file.
    :vartype sched: :class:`bridgedb.schedule.ScheduledInterval`
    :ivar sched: A time interval. After this amount time has passed, the
        CAPTCHA is considered stale, and all solutions are considered invalid
        regardless of their correctness.

    .. _gimp-captcha: https://github.com/isislovecruft/gimp-captcha
    """

    sched = schedule.ScheduledInterval(30, 'minutes')

    def __init__(self, publicKey=None, secretKey=None, hmacKey=None,
                 cacheImageDir=None, cacheAudioDir=None):
        """Create a ``GimpCaptcha`` which retrieves images from
        **cacheImageDir** and audio from **cacheAudioDir**.

        :param str publicKey: A PKCS#1 OAEP-padded, public RSA key, used for
            creating the ``captcha_challenge_field`` string to give to a
            client.
        :param str secretKey: A PKCS#1 OAEP-padded, private RSA key, used for
            verifying the client's solution to the CAPTCHA.
        :param bytes hmacKey: A client-specific HMAC secret key.
        :param str cacheImageDir: The local directory which pre-generated CAPTCHA
            images have been stored in. This can be set via the
            ``GIMP_CAPTCHA_DIR`` setting in the config file.
        :param str cacheAudioDir: The local directory which pre-generated CAPTCHA
            audio has been stored in. This can be set via the
            ``GIMP_CAPTCHA_AUDIO_DIR`` setting in the config file.
        :raises GimpCaptchaError: if :attr:`cacheImageDir` is not a directory.
        :raises GimpCaptchaError: if :attr:`cacheAudioDir` is not a directory.
        :raises CaptchaKeyError: if any of :attr:`secretKey`,
            :attr:`publicKey`, or :attr:`hmacKey` are invalid or missing.
        """

        # TODO: These don't and have failing unit tests.
        if not cacheImageDir or not os.path.isdir(cacheImageDir):
            raise GimpCaptchaError("GimpCaptcha image CAPTCHA cache isn't a"
                    + " directory: %r" % cacheImageDir)
        if cacheAudioDir and not os.path.isdir(cacheAudioDir):
            raise GimpCaptchaError("GimpCaptcha audio CAPTCHA cache isn't a"
                    + " directory: %r" % cacheAudioDir)

        if not (publicKey and secretKey and hmacKey):
            raise CaptchaKeyError(
                "Invalid key supplied to GimpCaptcha: SK=%r PK=%r HMAC=%r"
                % (secretKey, publicKey, hmacKey))

        super(GimpCaptcha, self).__init__(publicKey=publicKey,
                                          secretKey=secretKey)
        self.hmacKey = hmacKey
        self.cacheImageDir = cacheImageDir
        self.cacheAudioDir = cacheAudioDir
        self.answer = None

    @classmethod
    def check(cls, challenge, solution, secretKey, hmacKey):
        """Check a client's CAPTCHA **solution** against the **challenge**.

        :param str challenge: The contents of the
            ``'captcha_challenge_field'`` HTTP form field.
        :param str solution: The client's proposed solution to the CAPTCHA
            that they were presented with.
        :param str secretKey: A PKCS#1 OAEP-padded, private RSA key, used for
            verifying the client's solution to the CAPTCHA.
        :param bytes hmacKey: A private key for generating HMACs.
        :raises CaptchaExpired: if the **solution** was for a stale CAPTCHA.
        :rtype: bool
        :returns: ``True`` if the CAPTCHA solution was correct and not
            stale. ``False`` otherwise.
        """
        hmacIsValid = False

        if not solution:
            return hmacIsValid

        logging.debug("Checking CAPTCHA solution %r against challenge %r"
                      % (solution, challenge))
        try:
            decoded = urlsafe_b64decode(challenge)
            hmacFromBlob = decoded[:20]
            encBlob = decoded[20:]
            hmacNew = crypto.getHMAC(hmacKey, encBlob)
            hmacIsValid = hmacNew == hmacFromBlob
        except Exception:
            return False
        finally:
            if hmacIsValid:
                try:
                    answerBlob = secretKey.decrypt(encBlob)
                    timestamp = answerBlob[:12].lstrip('0')
                    then = cls.sched.nextIntervalStarts(int(timestamp))
                    now = int(time.time())
                    answer = answerBlob[12:]
                except Exception as error:
                    logging.warn(error.message)
                else:
                    # If the beginning of the 'next' interval (the interval
                    # after the one when the CAPTCHA timestamp was created)
                    # has already passed, then the CAPTCHA is stale.
                    if now >= then:
                        exp = schedule.fromUnixSeconds(then).isoformat(sep=' ')
                        raise CaptchaExpired("Solution %r was for a CAPTCHA "
                                             "which already expired at %s."
                                             % (solution, exp))
                    if solution.lower() == answer.lower():
                        return True
            return False

    def createChallenge(self, answer):
        """Encrypt-then-HMAC a timestamp plus the CAPTCHA **answer**.

        A challenge string consists of a URL-safe, base64-encoded string which
        contains an ``HMAC`` concatenated with an ``ENC_BLOB``, in the
        following form::

            CHALLENGE := B64( HMAC | ENC_BLOB )
            ENC_BLOB := RSA_ENC( ANSWER_BLOB )
            ANSWER_BLOB := ( TIMESTAMP | ANSWER )

        where
          * ``B64`` is a URL-safe base64-encode function,
          * ``RSA_ENC`` is the PKCS#1 RSA-OAEP encryption function,
          * and the remaining feilds are specified as follows:

        +-------------+--------------------------------------------+----------+
        | Field       | Description                                | Length   |
        +=============+============================================+==========+
        | HMAC        | An HMAC of the ``ENC_BLOB``, created with  | 20 bytes |
        |             | the client-specific :attr:`hmacKey`, by    |          |
        |             | applying :func:`~crypto.getHMAC` to the    |          |
        |             | ``ENC_BLOB``.                              |          |
        +-------------+--------------------------------------------+----------+
        | ENC_BLOB    | An encrypted ``ANSWER_BLOB``, created with | varies   |
        |             | a PKCS#1 OAEP-padded RSA :attr:`publicKey`.|          |
        +-------------+--------------------------------------------+----------+
        | ANSWER_BLOB | Contains the concatenated ``TIMESTAMP``    | varies   |
        |             | and ``ANSWER``.                            |          |
        +-------------+--------------------------------------------+----------+
        | TIMESTAMP   | A Unix Epoch timestamp, in seconds,        | 12 bytes |
        |             | left-padded with "0"s.                     |          |
        +-------------+--------------------------------------------+----------+
        | ANSWER      | A string containing answer to this         | 8 bytes  |
        |             | CAPTCHA :attr:`image`.                     |          |
        +-------------+--------------------------------------------+----------+

        The steps taken to produce a ``CHALLENGE`` are then:

        1. Create a ``TIMESTAMP``, and pad it on the left with ``0``s to 12
           bytes in length.
        2. Next, take the **answer** to this CAPTCHA :data:`image` and
           concatenate the padded ``TIMESTAMP`` and the ``ANSWER``, forming
           an ``ANSWER_BLOB``.
        3. Encrypt the resulting ``ANSWER_BLOB`` to :data:`publicKey` to
           create the ``ENC_BLOB``.
        4. Use the client-specific :data:`hmacKey` to apply the
           :func:`~crypto.getHMAC` function to the ``ENC_BLOB``, obtaining
           an ``HMAC``.
        5. Create the final ``CHALLENGE`` string by concatenating the
           ``HMAC`` and ``ENC_BLOB``, then base64-encoding the result.

        :param str answer: The answer to a CAPTCHA.
        :rtype: str
        :returns: A challenge string.
        """
        timestamp = str(int(time.time())).zfill(12)
        blob = timestamp + answer
        encBlob = self.publicKey.encrypt(blob)
        hmac = crypto.getHMAC(self.hmacKey, encBlob)
        challenge = urlsafe_b64encode(hmac + encBlob)
        return challenge

    def get(self):
        """Get a random CAPTCHA from the cache directory.

        This chooses a random CAPTCHA image file from the cache directory, and
        reads the contents of the image into a string. If :attr:`cacheAudioDir`
        is set, it attempts to load the corresponding audio CAPTCHA.

        Next, it creates a challenge string for the CAPTCHA, via
        :meth:`createChallenge`.

        :raises GimpCaptchaError: if the chosen CAPTCHA image file could not
            be read, or if the :attr:`cacheImageDir` is empty.
        :rtype: tuple
        :returns: A 3-tuple containing the image file contents as a string,
            the audio file contents as a string, and a challenge string (used
            for checking the client's solution).
        """
        try:
            imageFilename = random.choice(os.listdir(self.cacheImageDir))
            imagePath = os.path.join(self.cacheImageDir, imageFilename)
            with open(imagePath) as imageFile:
                self.image = imageFile.read()
        except IndexError:
            raise GimpCaptchaError("CAPTCHA image cache dir appears empty: %r"
                                   % self.cacheImageDir)
        except (OSError, IOError):
            raise GimpCaptchaError("Could not read Gimp captcha image file: %r"
                                   % imageFilename)
        # If the cacheAudioDir is defined, we'll try to load the cache image.
        # Otherwise, we're just returning an empty string.
        if self.cacheAudioDir:
            try:
                # We're dependent on the files having name.extension naming.
                audioFilename = imageFilename.split('.')[0] + ".wav"
                audioPath = os.path.join(self.cacheAudioDir, audioFilename)
                with open(audioPath) as audioFile:
                    self.audio = audioFile.read()
            except IndexError:
                raise GimpCaptchaError("CAPTCHA audio cache dir not complete: %r"
                        % self.cacheAudioDir)
            except (OSError, IOError):
                raise GimpCaptchaError("Could not read Gimp captcha audio file: %r"
                        % audioFilename)
        else:
            self.audio = ''

        self.answer = imageFilename.rsplit(os.path.extsep, 1)[0]
        self.challenge = self.createChallenge(self.answer)

        return (self.image, self.audio, self.challenge)
