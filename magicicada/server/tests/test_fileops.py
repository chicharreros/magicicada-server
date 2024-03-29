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

"""Test file operations."""

from magicicadaprotocol import errors as protocol_errors, request
from twisted.internet import threads, defer

from magicicada.filesync import errors
from magicicada.filesync.models import STATUS_LIVE, STATUS_DEAD
from magicicada.server.testing.testcase import (
    TestWithDatabase,
    get_put_content_params,
)


class TestMove(TestWithDatabase):
    """Test the move command."""

    def test_move_file_same_dir(self):
        """Rename."""

        def auth(client):
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(self.save_req, 'root_id')
            d.addCallback(lambda r: client.make_file(request.ROOT, r, "hola"))
            d.addCallback(
                lambda mkfile_req: client.move(
                    request.ROOT,
                    mkfile_req.new_id,
                    self._state.root_id,
                    "chau",
                )
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_move_file_other_dir(self):
        """Rename and re-parent."""

        def auth(client):
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(self.save_req, 'root_id')
            d.addCallback(
                lambda root: client.make_file(request.ROOT, root, "hola")
            )
            d.addCallback(self.save_req, 'filereq')
            d.addCallback(
                lambda _: client.make_dir(
                    request.ROOT, self._state.root_id, "sub"
                )
            )
            d.addCallback(
                lambda mkdir_req: client.move(
                    request.ROOT,
                    self._state.filereq.new_id,
                    mkdir_req.new_id,
                    "chau",
                )
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_move_invalid_character(self):
        """Try to move a dir to a name with invalid characters and fail."""

        @defer.inlineCallbacks
        def auth(client):
            yield client.dummy_authenticate("open sesame")
            root = yield client.get_root()
            self.save_req(root, 'root_id')
            req = yield client.make_dir(request.ROOT, root, "hola")
            d = client.move(
                request.ROOT, req.new_id, self._state.root_id, "hola / "
            )
            res = yield self.assertFailure(d, request.StorageRequestError)
            self.assertEqual(str(res), "INVALID_FILENAME")

        return self.callback_test(auth, add_default_callbacks=True)

    def test_move_file_overwrite(self):
        """Rename over an existing file."""

        def auth(client):
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(self.save_req, 'root_id')
            d.addCallbacks(
                lambda r: client.make_file(request.ROOT, r, "hola"),
                client.test_fail,
            )
            d.addCallbacks(
                lambda _: client.make_file(
                    request.ROOT, self._state.root_id, "chau"
                ),
                client.test_fail,
            )
            d.addCallbacks(
                lambda mkfile: client.move(
                    request.ROOT, mkfile.new_id, self._state.root_id, "hola"
                ),
                client.test_fail,
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_move_generations(self):
        """Move a file and receive new generation."""

        @defer.inlineCallbacks
        def test(client):
            """Test."""
            yield client.dummy_authenticate("open sesame")

            # create the dir
            root_id = yield client.get_root()
            make_req = yield client.make_file(request.ROOT, root_id, "hola")

            # rename and check
            move_req = yield client.move(
                request.ROOT, make_req.new_id, root_id, "chau"
            )
            self.assertEqual(
                move_req.new_generation, make_req.new_generation + 1
            )

        return self.callback_test(test, add_default_callbacks=True)

    def test_move_inside_own_child(self):
        """Move inside own child.

        Not a very real situation, but we shouldn't crash on it.
        """

        @defer.inlineCallbacks
        def test(client):
            """Test."""
            yield client.dummy_authenticate("open sesame")

            # create one dir
            root_id = yield client.get_root()
            p_dir = yield client.make_dir(request.ROOT, root_id, "parent")

            # create child dir
            c_dir = yield client.make_dir(request.ROOT, p_dir.new_id, "child")

            # do unreal move
            try:
                yield client.move(
                    request.ROOT, p_dir.new_id, c_dir.new_id, "parent"
                )
            except protocol_errors.NoPermissionError:
                pass  # failed as we expected
            else:
                client.test_fail("It should have failed!")

        return self.callback_test(test, add_default_callbacks=True)


class TestUnlink(TestWithDatabase):
    """Test unlink command."""

    def test_unlink(self):
        """Test unlinking a file."""

        def auth(client):
            def get_file_status():
                file_id = self._state.file
                try:
                    file = self.usr0.get_node(file_id)
                except errors.DoesNotExist:
                    return STATUS_DEAD
                return file.status

            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallbacks(
                lambda r: client.make_file(request.ROOT, r, "hola"),
                client.test_fail,
            )
            d.addCallback(lambda req: self._save_state("file", req.new_id))
            d.addCallback(lambda _: threads.deferToThread(get_file_status))
            d.addCallback(lambda status: self.assertEqual(status, STATUS_LIVE))
            d.addCallbacks(
                lambda mkfile_req: client.unlink(
                    request.ROOT, self._state.file
                ),
                client.test_fail,
            )
            d.addCallback(lambda _: threads.deferToThread(get_file_status))
            d.addCallback(lambda status: self.assertEqual(status, STATUS_DEAD))
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_unlink_root(self):
        """Test unlinking a file."""

        def auth(client):
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(
                lambda r: client.unlink(
                    request.ROOT,
                    r,
                )
            )
            self.assertFails(d, "NO_PERMISSION")
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_unlink_dir(self):
        """Test unlinking a dir."""

        def auth(client):
            def get_dir_status():
                file_id = self._state.file
                try:
                    file = self.usr0.get_node(file_id)
                except errors.DoesNotExist:
                    return STATUS_DEAD
                return file.status

            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallbacks(lambda r: client.make_dir(request.ROOT, r, "hola"))
            d.addCallback(lambda req: self._save_state("file", req.new_id))
            d.addCallback(lambda _: threads.deferToThread(get_dir_status))
            d.addCallback(lambda status: self.assertEqual(status, STATUS_LIVE))
            d.addCallbacks(
                lambda mkfile_req: client.unlink(
                    request.ROOT, self._state.file
                ),
                client.test_fail,
            )
            d.addCallback(lambda _: threads.deferToThread(get_dir_status))
            d.addCallback(lambda status: self.assertEqual(status, STATUS_DEAD))
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_move_from_unlinked_file(self):
        """Test moving and unlinked file."""

        def auth(client):
            # setup
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create file and remove it
            d.addCallback(lambda r: client.make_file(request.ROOT, r, "hola"))
            d.addCallback(lambda req: self._save_state("file", req.new_id))
            d.addCallback(
                lambda _: client.unlink(request.ROOT, self._state.file)
            )

            # move it to another destination
            d.addCallback(
                lambda _: client.move(
                    request.ROOT, self._state.file, self._state.root, "chau"
                )
            )
            d.addCallbacks(client.test_fail, client.check_doesnotexist)

        return self.callback_test(auth)

    def test_move_to_unlinked_file(self):
        """Test moving a file to an unlinked file."""

        def auth(client):
            # setup
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create file and remove it
            d.addCallback(
                lambda _: client.make_file(
                    request.ROOT, self._state.root, "chau"
                )
            )
            d.addCallback(lambda req: client.unlink(request.ROOT, req.new_id))

            # create new file and move over the previous one
            d.addCallback(
                lambda _: client.make_file(
                    request.ROOT, self._state.root, "hola"
                )
            )
            d.addCallback(
                lambda req: client.move(
                    request.ROOT, req.new_id, self._state.root, "chau"
                )
            )

            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_mkfile_on_unlinked_file(self):
        """Test creating a file like an unlinked file."""

        def auth(client):
            # setup
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create file and remove it
            d.addCallback(
                lambda _: client.make_file(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallback(lambda req: client.unlink(request.ROOT, req.new_id))

            # create new file, same name that before
            d.addCallback(
                lambda _: client.make_file(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_mkdir_on_unlinked_dir(self):
        """Test creating a dir like an unlinked dir."""

        def auth(client):
            # setup
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create dir and remove it
            d.addCallback(
                lambda _: client.make_dir(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallback(lambda req: client.unlink(request.ROOT, req.new_id))

            # create new dir, same name that before
            d.addCallback(
                lambda _: client.make_dir(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_mkfile_on_unlinked_dir(self):
        """Test creating a file like an unlinked dir."""

        def auth(client):
            # setup
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create dir and remove it
            d.addCallback(
                lambda _: client.make_dir(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallback(lambda req: client.unlink(request.ROOT, req.new_id))

            # create file, same name that previous dir
            d.addCallback(
                lambda _: client.make_file(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_mkdir_on_unlinked_file(self):
        """Test creating a dir like an unlinked file."""

        def auth(client):
            # setup
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create file and remove it
            d.addCallback(
                lambda _: client.make_file(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallback(lambda req: client.unlink(request.ROOT, req.new_id))

            # create dir, same name that previous file
            d.addCallback(
                lambda _: client.make_dir(
                    request.ROOT, self._state.root, "name"
                )
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_getcontent_unlinked(self):
        """Test getting the content of an unlinked file."""

        def auth(client):
            # setup
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda r: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create file and remove it
            d.addCallback(
                lambda _: client.make_file(
                    request.ROOT, self._state.root, "hola"
                )
            )
            d.addCallback(lambda req: client.unlink(request.ROOT, req.new_id))

            d.addCallbacks(
                lambda r: client.get_content(
                    request.ROOT, self._state.root, "hola"
                ),
                client.test_fail,
            )
            d.addCallbacks(client.test_fail, lambda x: client.test_done("ok"))

        return self.callback_test(auth)

    @defer.inlineCallbacks
    def test_putcontent_unlinked(self):
        """Try to put content in an unlinked file."""
        data = b"*"

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        # create file and remove it
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        client.unlink(params['share'], params['node'])

        # try to put content
        d = client.put_content(**params)
        yield self.assertFails(d, 'DOES_NOT_EXIST')

    def test_unlink_and_create_same_name(self):
        """Unlink a dir, and create it again with same name."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda _: client.get_root())
            d.addCallback(lambda r: self._save_state("root", r))

            # create a subdir in root
            d.addCallback(
                lambda root: client.make_dir(request.ROOT, root, "tdir")
            )

            # delete the dir
            d.addCallback(lambda r: client.unlink(request.ROOT, r.new_id))

            # create the dir again, with same name
            d.addCallback(
                lambda _: client.make_dir(
                    request.ROOT, self._state.root, "tdir"
                )
            )

            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_unlink_generations(self):
        """Remove a dir and receive new generation."""

        @defer.inlineCallbacks
        def test(client):
            """Test."""
            yield client.dummy_authenticate("open sesame")

            # create the dir
            root_id = yield client.get_root()
            make_req = yield client.make_dir(request.ROOT, root_id, "hola")

            # remove and check
            unlink_req = yield client.unlink(request.ROOT, make_req.new_id)
            self.assertEqual(
                unlink_req.new_generation, make_req.new_generation + 1
            )

        return self.callback_test(test, add_default_callbacks=True)


class TestPublicFiles(TestWithDatabase):
    """Test the public files management."""

    def test_set_public_file_true(self):
        @defer.inlineCallbacks
        def auth(client):
            yield client.dummy_authenticate("open sesame")
            root = yield client.get_root()
            req = yield client.make_file(request.ROOT, root, "hola")
            resp = yield client.change_public_access(
                request.ROOT, req.new_id, True
            )
            fileobj = self.usr0.get_node(req.new_id)
            self.assertTrue(fileobj.is_public)
            self.assertEqual(resp.public_url, fileobj.public_url)

        return self.callback_test(auth, add_default_callbacks=True)

    def test_set_public_file_false(self):
        @defer.inlineCallbacks
        def auth(client):
            yield client.dummy_authenticate("open sesame")
            root = yield client.get_root()
            req = yield client.make_file(request.ROOT, root, "hola")

            # set it to public first
            yield client.change_public_access(request.ROOT, req.new_id, True)
            fileobj = self.usr0.get_node(req.new_id)
            assert fileobj.is_public

            # set it to false, check
            yield client.change_public_access(request.ROOT, req.new_id, False)
            fileobj = self.usr0.get_node(req.new_id)
            self.assertFalse(fileobj.is_public)

        return self.callback_test(auth, add_default_callbacks=True)

    def test_list_public_files_none(self):
        @defer.inlineCallbacks
        def auth(client):
            yield client.dummy_authenticate("open sesame")

            # list and check
            resp = yield client.list_public_files()
            self.assertEqual(resp.public_files, [])

        return self.callback_test(auth, add_default_callbacks=True)

    def test_list_public_files_several(self):
        @defer.inlineCallbacks
        def auth(client):
            yield client.dummy_authenticate("open sesame")
            root = yield client.get_root()

            # create three files, and set two of them to be public
            req1 = yield client.make_file(request.ROOT, root, "file1")
            yield client.make_file(request.ROOT, root, "file2")
            req3 = yield client.make_file(request.ROOT, root, "file3")
            yield client.change_public_access(request.ROOT, req1.new_id, True)
            yield client.change_public_access(request.ROOT, req3.new_id, True)

            # list and check
            resp = yield client.list_public_files()
            self.assertEqual(
                {node.node_id for node in resp.public_files},
                set([req1.new_id, req3.new_id]),
            )

        return self.callback_test(auth, add_default_callbacks=True)

    def test_list_public_files_unpublished(self):
        @defer.inlineCallbacks
        def auth(client):
            yield client.dummy_authenticate("open sesame")
            root = yield client.get_root()

            # create a file, publish, and assert
            req = yield client.make_file(request.ROOT, root, "file")
            yield client.change_public_access(request.ROOT, req.new_id, True)
            resp = yield client.list_public_files()
            assert [node.node_id for node in resp.public_files] == [req.new_id]

            # unpublish it and check
            yield client.change_public_access(request.ROOT, req.new_id, False)
            resp = yield client.list_public_files()
            self.assertEqual(resp.public_files, [])

        return self.callback_test(auth, add_default_callbacks=True)
