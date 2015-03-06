__author__ = 'Alva'
import HSAlib


class request():
    def __init__(self, uuid):
        self.resource_uuid = uuid
    def uuid(self): return self.resource_uuid

def get_user(r):
    return r.resource_uuid

ha = HSAlib.HSAccess("admin", 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

class ResourcePermissionsMixin():
    def __init__(self, uuid):
        # my assumption that the login of the user will be used in creating the DB seems to be misplaced.
        self.resource_uuid = uuid

    # creator = models.ForeignKey(User,
    #                             related_name='creator_of_%(app_label)s_%(class)s',
    #                             help_text='This is the person who first uploaded the resource',
    #                             )
    #
    # public = models.BooleanField(
    #     help_text='If this is true, the resource is viewable and downloadable by anyone',
    #    default=True
    # )
    # DO WE STILL NEED owners?
    # owners = models.ManyToManyField(User,
    #                                 related_name='owns_%(app_label)s_%(class)s',
    #                                 help_text='The person who uploaded the resource'
    # )
    # frozen = models.BooleanField(
    #     help_text='If this is true, the resource should not be modified',
    #     default=False
    # )
    # do_not_distribute = models.BooleanField(
    #     help_text='If this is true, the resource owner has to designate viewers',
    #     default=False
    # )
    # discoverable = models.BooleanField(
    #     help_text='If this is true, it will turn up in searches.',
    #     default=True
    # )
    # published_and_frozen = models.BooleanField(
    #     help_text="Once this is true, no changes can be made to the resource",
    #     default=False
    # )
    #
    # view_users = models.ManyToManyField(User,
    #                                     related_name='user_viewable_%(app_label)s_%(class)s',
    #                                     help_text='This is the set of Hydroshare Users who can view the resource',
    #                                     null=True, blank=True)
    #
    # view_groups = models.ManyToManyField(Group,
    #                                      related_name='group_viewable_%(app_label)s_%(class)s',
    #                                      help_text='This is the set of Hydroshare Groups who can view the resource',
    #                                      null=True, blank=True)
    #
    # edit_users = models.ManyToManyField(User,
    #                                     related_name='user_editable_%(app_label)s_%(class)s',
    #                                     help_text='This is the set of Hydroshare Users who can edit the resource',
    #                                     null=True, blank=True)
    #
    # edit_groups = models.ManyToManyField(Group,
    #                                      related_name='group_editable_%(app_label)s_%(class)s',
    #                                      help_text='This is the set of Hydroshare Groups who can edit the resource',
    #                                      null=True, blank=True)

    # resource_uuid = models.StringField(...)
    class Meta:
        abstract = True


    # @property
    # def permissions_store(self):
    #     # return s.PERMISSIONS_DB
    #     return None

    def can_add(self, request):
        return self.can_change(request)

    def can_delete(self, request):
        global ha
        user_uuid = get_user(request)
        return ha.resource_is_owned(self.resource_uuid,user_uuid)

    def can_change(self, request):
        global ha
        user_uuid = get_user(request)
        return ha.resource_is_readwrite(self.resource_uuid, user_uuid)

        # if user.is_authenticated():
        #     if user.is_superuser:
        #         ret = True
        #     elif self.creator and user.pk == self.creator.pk:
        #         ret = True
        #     elif user.pk in { o.pk for o in self.owners.all() }:
        #         ret = True
        #     elif self.edit_users.filter(pk=user.pk).exists():
        #         ret = True
        #     elif self.edit_groups.filter(pk__in=set(g.pk for g in user.groups.all())):
        #         ret = True
        #     else:
        #         ret = False
        # else:
        #     ret = False
        #
        # return ret


    def can_view(self, request):
        user_uuid = get_user(request)
        global ha
        return ha.resource_is_readable(self.resource_uuid, user_uuid)

        # if self.public:
        #     return True
        # if user.is_authenticated():
        #     if user.is_superuser:
        #         ret = True
        #     elif self.creator and user.pk == self.creator.pk:
        #         ret = True
        #     elif user.pk in { o.pk for o in self.owners.all() }:
        #         ret = True
        #     elif self.view_users.filter(pk=user.pk).exists():
        #         ret = True
        #     elif self.view_groups.filter(pk__in=set(g.pk for g in user.groups.all())):
        #         ret = True
        #     else:
        #         ret = False
        # else:
        #     ret = False
        #
        # return ret

# test this
def setup(login):
    return HSAlib.HSAccess(login, 'unused', 'acouch', 'acouch', 'xyzzy', 'localhost', '5432')

# set up some interesting stuff
ha = setup('admin')
ha._global_reset("yes, I'm sure")
ha.assert_user('foo', 'foo', True, False, 'foo')
ha.assert_user('bar', 'bar', True, False, 'bar')

ha = setup('foo')
ha.assert_resource('/foo/cat','all about foo', False, 'cat', 'foo')
ha = setup('bar')
ha.assert_resource('/bar/dog', 'all about dogs', False, 'dog', 'bar')
ha.share_resource_with_user('dog', 'foo', 'ro')
print ha.get_users()

r = ResourcePermissionsMixin('dog')
req_foo = request('foo')
req_bar = request('bar')
print r, req_foo

print "foo can read r? ", r.can_view(req_foo)
print "bar can read r? ", r.can_view(req_bar)
print "foo can change r? ", r.can_change(req_foo)
print "bar can change r? ", r.can_change(req_bar)
print "foo can delete r? ", r.can_delete(req_foo)
print "bar can delete r", r.can_delete(req_bar)


