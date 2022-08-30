# Copyright 2008-2015 Canonical
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For further info, check  http://launchpad.net/magicicada-server

"""Some utility functions used by the DAL."""

import base64
import re
import unicodedata
import uuid

from django.conf import settings

MAX_IS_IN_SIZE = 50


def split_in_list(inlist, max=MAX_IS_IN_SIZE):
    """Split a list into a list of list."""
    if len(inlist) > max:
        last = len(inlist)
        return [inlist[i:min(last, i + max)] for i in range(0, last, max)]
    else:
        return [inlist]


def encode_hash(hash_value):
    return hash_value.encode('utf-8') if hash_value is not None else None


def encode_uuid(uuid_value):
    """Encode a UUID, or any string value."""
    if uuid_value:
        if isinstance(uuid_value, uuid.UUID):
            uuid_value = uuid_value.bytes
        elif isinstance(uuid_value, str):
            uuid_value = uuid_value.encode('utf-8')
        result = base64.urlsafe_b64encode(uuid_value).strip(b'=')
        return result.decode('utf8')


def decode_uuid(encoded, label=''):
    """Return a uuid from the encoded value.

    If the value isn't UUID, just return the decoded value

    """
    encoded += '=' * (-len(encoded) % 4)

    assert isinstance(encoded, str)
    try:
        encoded = encoded.encode('ascii')
    except UnicodeEncodeError:
        raise NodeKeyParseError('nodekey should be an ASCII string')

    try:
        value_bytes = base64.urlsafe_b64decode(encoded)
    except ValueError:
        raise NodeKeyParseError(
            'Could not decode %r portion of node key' % label)
    try:
        value_id = uuid.UUID(bytes=value_bytes)
    except ValueError:
        raise NodeKeyParseError('%s portion of node key is not a uuid' % label)

    return value_id


NODEKEY_RE = r'[A-Za-z0-9_-]{22}(?::[A-Za-z0-9_-]{22})?'


def make_nodekey(share_id, node_id):
    """Create a key for finding nodes.

    This is needed when shares are involved so the correct database can be
    determined via the share.
    """
    if share_id:
        strkey = '%s:%s' % (encode_uuid(share_id), encode_uuid(node_id))
    else:
        strkey = encode_uuid(node_id)
    return strkey


class NodeKeyParseError(Exception):
    """The node key could not be parsed."""


def parse_nodekey(nodekey):
    """Parse a string into a (volume_id, node_id) tuple."""
    if ':' in nodekey:
        encoded_volume, nodekey = nodekey.split(':', 1)
    else:
        encoded_volume = ''
    if encoded_volume:
        volume_id = decode_uuid(encoded_volume, label='volume')
    else:
        volume_id = None
    node_id = decode_uuid(nodekey, label='node')
    return volume_id, node_id


class Base62Error(Exception):
    """Error encoding or decoding base-32 string."""


_base62_digits = (
    '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')


_base62_values = [-1] * 256


for _value, _char in enumerate(_base62_digits):
    _base62_values[ord(_char)] = _value


def encode_base62(value, padded_to=0):
    """Encode a positive integer as a base-62 string."""
    if value <= 0:
        raise Base62Error('Can only encode positive numbers')
    digits = []
    while value > 0:
        digits.append(_base62_digits[value % 62])
        value //= 62
    digits.reverse()
    encoded_value = ''.join(digits)
    if padded_to:
        if len(digits) > padded_to:
            raise Base62Error('Insufficent padding size.')
        encoded_value = encoded_value.rjust(padded_to, '0')
    return encoded_value


def decode_base62(string, allow_padding=False):
    """Decode a base-62 string to a positive integer."""
    assert isinstance(string, str)
    if not allow_padding and string.startswith(_base62_digits[0]):
        raise Base62Error('base62 strings may not begin with zero')
    if len(string) == 0:
        raise Base62Error('Can not decode an empty string')
    value = 0
    for char in string:
        digit = _base62_values[ord(char)]
        if digit < 0:
            raise Base62Error('Unknown base62 digit')
        value = value * 62 + digit
    if not 0 <= value < 1 << 128:
        raise Base62Error('Value is out of range for uuid.')
    return value


def get_node_public_key(node):
    """Get a node's public_key."""
    if node.public_uuid is not None:
        return encode_base62(node.public_uuid.int, padded_to=22)


def get_public_file_url(node):
    """Return the url to a public file."""
    public_key = get_node_public_key(node)
    if public_key is not None:
        return '%s/%s' % (settings.PUBLIC_URL_PREFIX.rstrip('/'), public_key)


def get_keywords_from_path(volume_path):
    """Split keywords from a volume path."""
    # we do not index the root volume path
    clean_path = volume_path.replace(settings.ROOT_USERVOLUME_PATH, '')
    clean_path = unicodedata.normalize('NFKD', clean_path)
    clean_path = clean_path.encode('ASCII', 'ignore').lower().decode('utf-8')
    keywords = re.findall(r'\w+', clean_path)
    # convert to set for unique values
    return set(keywords)
