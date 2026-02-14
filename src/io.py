from datetime import datetime, timedelta
from typing import Optional, Callable
from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi import Response
import sys, os, json, types
import inspect

from formatize.const import *

from formatize.form import\
  ADMIN, ACCOUNTING,\
  APP_PATH, DBA_PATH,\
  PARAMS, EMPTY, SPACE,\
  add_models_from_yaml,\
  add_consts_from_yaml,\
  get_modules_from_yaml,\
  param_load_from_request,\
  data_load_from_json_file,\
  data_load_from_yaml_file,\
  function_module2,\
  function_module,\
  import_module,\
  get_module,\
  load_yaml,\
  dump_yaml,\
  dump_csv,\
  popattr,\
  popfunc,\
  uid,\
  sha,\
  lds,\
  hstr,\
  dicts,\
  integer,\
  default,\
  flatten,\
  extract,\
  to_upper,\
  err_input,\
  is_numeric,\
  str_to_list,\
  check_list,\
  merge_list,\
  data_dict,\
  sort_dict,\
  dict_sort,\
  dict_assign,\
  parse_doc_date,\
  prepare_model,\
  prepare_info,\
  prepare_password,\
  prepare_worktime,\
  prepare_workinterval,\
  prepare_hash_password

from embedize import\
  ARRAY,\
  ERROR,\
  RESULT,\
  UNKNOWN,\
  BADZONEID,\
  ERRORINPUT,\
  NOROWCOUNT,\
  DEFPASSWORD,\
  ADMINZONENAME,\
  ADMINUSERNAME,\
  ADMINZONE,\
  ADMINUSER,\
  NOENTRIES,\
  NOBALANCE,\
  COL_ID,\
  COL_UUID,\
  COL_NAME,\
  COL_ZONE,\
  COL_ZADM,\
  COL_PASS,\
  COL_OPWD,\
  COL_NPWD,\
  COL_INFO,\
  COL_ZONEID,\
  COL_ZONEIDN,\
  COL_CONUSER,\
  COL_USERIDN,\
  COL_CREATOR,\
  COL_MODIFIER,\
  COL_CREDIT,\
  COL_DEBIT,\
  COL_DATED,\
  COL_USER,\
  COL_CODE,\
  COL_ACCOUNT,\
  COL_ACCOUNTCODE,\
  duckdb,\
  sqlite3,\
  set_engine,\
  set_connect,\
  connect_duckdb,\
  connect_sqlite,\
  error_unexpect,\
  error_database,\
  dicts_items,\
  dict_result,\
  check_admin,\
  get_zoneid,\
  zonedb,\
  callup,\
  batch,\
  db_exist,\
  first_row,\
  import_zone_database,\
  export_zone_database,\
  export_database_tables,\
  resultset_first_row,\
  resultset_is_empty,\
  select_value,\
  select_dict,\
  select_list,\
  delete_one,\
  insert_one,\
  update_one,\
  delete_many,\
  insert_many,\
  update_many,\
  create_admin_zones,\
  create_admin_users,\
  duck_create_admin_zones,\
  duck_create_admin_users,\
  create_zone_roles,\
  create_zone_specs,\
  create_zone_specroles,\
  create_zone_userroles,\
  create_zone_userspecs,\
  create_zone_groups,\
  create_zone_roots,\
  create_zone_accounts,\
  create_zone_subs,\
  create_zone_items,\
  create_zone_txs,\
  duck_create_zone_roles,\
  duck_create_zone_specs,\
  duck_create_zone_specroles,\
  duck_create_zone_userspecs,\
  duck_create_zone_userroles,\
  duck_create_zone_groups,\
  duck_create_zone_roots,\
  duck_create_zone_accounts,\
  duck_create_zone_subs,\
  duck_create_zone_items,\
  duck_create_zone_txs,\
  multi_holders

LIBPATH = 'lib.db.query'

ROLE_WORKING = 'User login required'
ROLE_ADMIN = 'System admin privileges required'
ROLE_MANAGER = 'Client admin or system moderator or registered user access only'
ROLE_MODERATOR = 'System moderator privileges required'
ROLE_ZONE_ADMIN = 'Client admin privileges required'
ROLE_ZONE_MANAGER = 'Client admin or system moderator privileges required'
ROLE_ZONE_STAFF = 'Personnel login required'
ROLE_ADDITIONAL = 'Additional privileges required'
ROLE_CREATOR = 'Action dedicated for system admin on system zone and system moderator on client zones'
ROLE_USER = 'Action not authorized'

ROLE_FinancialRecordkeeping = 100100
ROLE_TransactionProcessing = 100150
ROLE_FinancialReporting = 100200
ROLE_AccountReconciliation = 100250
ROLE_TaxCompliance = 100300
ROLE_BudgetingForecasting = 100350
ROLE_Auditing = 100400
ROLE_FinancialAnalysis = 100450
ROLE_Compliance = 100500
ROLE_CostManagement = 100550
ROLE_AccountsPayableReceivable = 100600
ROLE_PayrollProcessing = 100650
ROLE_CommunicationCollaboration = 100700
ROLE_RecordReportReviewing = 100900

SPEC_StaffAccountant = 101100
SPEC_AccountingAssistant = 101150
SPEC_AccountingClerk = 101200
SPEC_FinancialAccountant = 101250
SPEC_TaxAccountant = 101300
SPEC_AuditAccountant = 101350
SPEC_ChiefAccountant = 101800
SPEC_FinancialOfficer = 101850
SPEC_Reviewer = 101900

## Overrode by IO.YAML config vars
edata_spec_specs = [SPEC_FinancialOfficer]
edata_role_specs = [SPEC_ChiefAccountant, SPEC_FinancialOfficer]
edata_sub_specs = [SPEC_StaffAccountant, SPEC_AccountingClerk, SPEC_FinancialAccountant, SPEC_TaxAccountant, SPEC_ChiefAccountant, SPEC_FinancialOfficer]
edata_txp_roles = [ROLE_TransactionProcessing]
edata_frk_roles = [ROLE_FinancialRecordkeeping]

ENV_SECRET = 'SECRET_KEY'
TOKENTYPE = 'token_type'
TOKEN = 'access_token'
RTOKEN = 'refresh_token'
TOKENID = 'sub'
BEARER = 'Bearer'
USERNAME = 'user'
MESSAGE = 'message'

ERR_DBASE = 'Database already exists'
ERR_NODBASE = 'Database does not exist'
ERR_OLDPASS = 'Incorrect given password'
ERR_USERNAME = 'Incorrect user name or status'
ERR_USERPASS = 'Incorrect user login password'
ERR_VALIDATES = 'Could not validate credentials'
ERR_AUTHLOGIN = 'Not authorized or login failed'
ERR_BADZONEID = 'Invalid zone ID'

ERR_INPUT = 'Invalid input parameters'
ERR_FUNCTION = 'App module or function not found'
ERR_JSONDATA = 'JSON input data processing failed'
ERR_LOADJSON = 'JSON data loading failed'
ERR_LOADYAML = 'YAML data loading failed'

JAFARG = 'afarg'
JMODEL = 'model'
JDFUNC = 'dfunc'
JDBMOD = 'dbmod'
JDBQUE = 'dbque'
JQUEID = 'queid'

json_role = lambda module: f'lib/json/{module}/role.json'
json_account = lambda module: f'lib/json/{module}/account.json'
yaml_transaction = lambda module: f'lib/yaml/{module}/transaction.yaml'
yaml_report = lambda module: f'lib/yaml/{module}/report.yaml'
yaml_rich = lambda module: f'lib/yaml/{module}/rich.yaml'

get_userid = lambda params: params.get(COL_USER)
get_idname = lambda params: params.get(COL_NAME) or params.get(COL_ID)
get_nameid = lambda params: params.get(COL_ID) or params.get(COL_NAME)

pseudo = lambda data: (lambda anything=None: data)
do_none = lambda access_token=None, param=None, ok=True: (ok, None, None)

popthis = lambda attr: popattr(this, attr)
get_attr = lambda attr: (lambda object: object.get(attr))

getfunc = lambda funcname, field, defval=None, finval=None, pop=popthis, module=None: pop(x[funcname].get(field) if type(x:=(y:=module or module_access).get(function_module2(y, funcname))) is dict and funcname in x else defval) or finval

get_afunc = lambda funcname, field='afunc', defval=None, finval=None, pop=popthis: getfunc(funcname, field, defval, finval, pop)
get_pfunc = lambda funcname, defval=get_idname, field='afarg': defval if not (x:=get_afunc(funcname, field=field, pop=hstr)) else (lambda p: p.get(x))
get_wfunc = lambda funcname, defval=prepare_password: get_afunc(funcname, field='wfunc', finval=defval if defval else prepare_password)
get_ifunc = lambda funcname, defval=prepare_info: get_afunc(funcname, field='ifunc', finval=defval if defval else prepare_info)
get_dfunc = lambda funcname, defval=select_dict: get_afunc(funcname, field='dfunc', finval=defval if defval else select_dict)
get_model = lambda funcname, defval=None, afunc=get_afunc: afunc(funcname, field='model', defval=defval, finval=popthis('DbUni'))
get_token = lambda funcname, defval=None: get_pfunc(funcname, defval=defval, field='token')
get_bfunc = lambda funcname, defval=None: get_afunc(funcname, field='bfunc', finval=defval)
get_rfunc = lambda funcname, defval=None: get_afunc(funcname, field='rfunc', finval=defval)
get_mfunc = lambda funcname, defval=None: get_afunc(funcname, field='mfunc', finval=defval)
get_minfo = lambda funcname, defval=None: get_afunc(funcname, field='minfo', finval=defval)
get_mdele = lambda funcname, defval=None: get_afunc(funcname, field='mdele', finval=defval)
get_erole = lambda funcname, defval=None: get_afunc(funcname, field='erole', finval=defval)
get_edata = lambda funcname, defval=None: get_afunc(funcname, field='edata', finval=defval)
get_build = lambda funcname, defval=None: get_afunc(funcname, field='build', defval=defval, finval=popthis('DbUni'))
get_query = lambda funcname, querypath, libpath=LIBPATH: popattr(get_module(querypath, path=f'{libpath}.'), funcname)
get_qpath = lambda funcname, defval=None, field='qpath': get_afunc(funcname, field=field, defval=EMPTY, finval=defval, pop=hstr)
get_rpath = lambda funcname, defval=None: get_qpath(funcname, defval, field='rpath')
get_rquid = lambda funcname, defval=None: get_qpath(funcname, defval, field='rquid')
get_afarg = lambda funcname, defval=None: get_qpath(funcname, defval, field='afarg')
get_mprep = lambda funcname, defval=None: get_afunc(funcname, field='mprep', finval=defval)
get_ufunc = lambda funcname, defval=None: get_afunc(funcname, field='ufunc', finval=defval)
get_cfunc = lambda funcname, defval=None: get_afunc(funcname, field='cfunc', finval=defval)
get_cemsg = lambda funcname, defval=None: get_afunc(funcname, field='cemsg', finval=defval)
get_cattr = lambda funcname, defval=None: get_qpath(funcname, defval, field='cattr')
get_vfunc = lambda funcname, defval=None: get_afunc(funcname, field='vfunc', finval=defval)
get_vattr = lambda funcname, defval=None: get_qpath(funcname, defval, field='vattr')

pick_afunc = lambda funcname, field='afunc', defval=None, finval=None, pop=popthis: getfunc(funcname, field, defval, finval, pop, module=module_dbase)
pick_dfunc = lambda funcname, defval=select_dict: pick_afunc(funcname, field='dfunc', finval=defval if defval else select_dict)
pick_qpath = lambda funcname, defval=None, field='qpath': pick_afunc(funcname, field=field, defval=EMPTY, finval=defval, pop=hstr)
pick_layer = lambda funcname, defval=None: x if (x:=integer(pick_qpath(funcname, defval, field='layer'))) > 0 else defval
pick_ufunc = lambda funcname, defval=None: pick_afunc(funcname, field='ufunc', finval=defval)
pick_model = lambda funcname, defval=None: get_model(funcname, defval, afunc=pick_afunc)
pick_rpath = lambda funcname, defval=None: pick_qpath(funcname, defval, field='rpath')
pick_rquid = lambda funcname, defval=None: pick_qpath(funcname, defval, field='rquid')

check_idname = lambda model, idname: False if not idname else (str(idname) if not is_numeric(idname, int) else str(idname)).strip().lower() in [str(model.id).lower(), str(model.name).lower()]
check_nameid = lambda obj, idname: False if not idname else (str(idname) if not is_numeric(idname, int) else str(idname)).strip().lower() in [str(obj.get('name')).lower(),str(obj.get('id')).lower()]
check_nameids = lambda obj, idnames: False if type(idnames) is not list else check_list([str(x).lower() for x in idnames], [str(obj.get('name')).lower(),str(obj.get('id')).lower()])
check_idnames = lambda lst, idnames: False if type(idnames) is not list else check_list([str(x).strip().lower() for x in idnames], [str(x).strip().lower() for x in lst])

get_yaml_querid = lambda module, querid: data_load_from_yaml_file(yaml_rich(module))[PARAMS].get(querid)
get_rich_query = lambda params, que='querid', mod='module': '' if not (mod:=params.get(mod)) or not (que:=params.get(que)) else get_yaml_querid(mod,que)
get_rich_retquery = lambda params, que='requerid', mod='module': get_rich_query(params, que, mod)

def access_function(caller: str, model: BaseModel=None, dfunc: Callable=None, layer=5, access=True) -> tuple:
  model = model or get_model(caller) if access else pick_model(caller)
  dfunc = dfunc or get_dfunc(caller) if access else pick_dfunc(caller)
  query = get_query(caller, get_qpath(caller) if access else pick_qpath(caller))
  retquery = get_query(get_rquid(caller), get_rpath(caller)) if access else get_query(pick_rquid(caller), pick_rpath(caller))
  dbfunc = lambda modelval, zoneid=None, query=query: dfunc(query=query, retquery=retquery, model=modelval, db_path=zonedb(zoneid), layer=layer)
  valid = model and dfunc and query and True
  return dbfunc, valid, query

def dbase_function(caller: str, model: BaseModel=None, dfunc: Callable=None, layer=5) -> tuple:
  return access_function(caller=caller, model=model, dfunc=dfunc, layer=layer, access=False)

def access_function0(*a, **kw):
  f, v, q = access_function(*a, **kw)
  return f if v else None

def dbase_function0(*a, **kw):
  f, v, q = dbase_function(*a, **kw)
  return f if v else None

""" Usage
def select_system_moderator(model, zoneid=None):
  f, v, q = dbase_function(callup(1), layer=4)
  return f(model, zoneid) if v else None
select_system_moderator(DbUser(name='admin'))
"""

def create_module(name: str):
  new_module = types.ModuleType(name)
  sys.modules[name] = new_module
  return sys.modules[name]

def create_dbase_functions(moduledict: dict):
  for item in moduledict:
    exec(
      f'''def {item} (model=[], zoneid=None, layer={pick_layer(item) or 4}):
      f, v, q = dbase_function(callup(1), layer=layer)
      return f(model, zoneid) if v else None''',
      globals())

dbexist = lambda zoneid=0: db_exist(zonedb(zoneid))
errnodb = lambda: error_database(ERR_NODBASE)
errdb = lambda: error_database(ERR_DBASE)

genesis_zone = lambda: DbZone(**{'id':ADMINZONE, 'name':ADMINZONENAME, 'active':True})
genesis_user = lambda adminpass=DEFPASSWORD: DbUser(**{'zone':ADMINZONE, 'name':ADMINUSERNAME, 'hpwd':prepare_hash_password(adminpass), 'active':True, 'zadmin':True, 'creator':None})
adminzone = lambda zone: str(zone).strip().upper() in [str(ADMINZONE), str(ADMINZONENAME)]

base_origins = lambda base, ports: [base]+[base+':'+str(x) for x in ports] if type(base) is not list else base+[y+':'+str(x) for x in ports for y in base]
checkonly = lambda params={}: params.get('checkonly')
je = lambda data: data.get(ERROR)

load_data = lambda jsonfile: data_load_from_json_file(jsonfile)
get_roles = lambda module, data: data[PARAMS]['modules'][module]['roles']
get_specs = lambda module, data: data[PARAMS]['modules'][module]['specs']

get_groups = lambda module, data: data[PARAMS]['modules'][module]['accounts']
get_accounts = lambda groupcode, groups: groups[groupcode]['data']

group_roots = lambda groupcode, groups: [{'id': x['id'], 'grup': groups[groupcode]['id'], 'code': str(x['code']) if x['code'] else str(x['id']), 'name': x['name'], 'note': x['note'], 'active': x['active']} for x in get_accounts(groupcode, groups)]
root_accounts = lambda groupcode, groups: [{'id': x['id'], 'root': x['id'], 'code': str(x['code']) if x['code'] else str(x['id']), 'name': x['name'], 'note': x['note'], 'subs': [{'id': y['id'], 'root': x['id'], 'code': y['code'] if y['code'] else str(y['id']), 'name': y['name'], 'note': y['note'], 'active': y['active']} for y in x['subs']], 'active': x['active']} for x in get_accounts(groupcode, groups)]
code_accounts = lambda groupcode, groups: flatten([row['subs'] if row['subs'] else [{'id': row['id'], 'root': row['id'], 'code': str(row['id']), 'name': row['name'], 'note': row['note'], 'active': row['active']}] for row in root_accounts(groupcode, groups)])

groups_scalar_data = lambda groups: [{'id':groups[x]['id'], 'code':x, 'name':groups[x]['name']} for x in groups]
roots_scalar_data = lambda groups: flatten([group_roots(x, groups) for x in groups])
accounts_scalar_data = lambda groups: flatten([code_accounts(x, groups) for x in groups])

check_user_at_spec = lambda user, spec, zoneid: not resultset_is_empty(select_userspec(DbUserspec(user=user, spec=spec), zoneid))
check_user_at_role = lambda user, role, zoneid: not resultset_is_empty(select_userrole(DbUserrole(user=user, role=role), zoneid))
check_user_of_specs = lambda user, specs, zoneid: check_list(select_user_specs(DbUserspec(user=user), zoneid)[RESULT], specs)
check_user_of_roles = lambda user, roles, zoneid: check_list(select_user_roles(DbUserrole(user=user), zoneid)[RESULT], roles)

under_specs = lambda user, specs: user.active and check_user_of_specs(user.id, specs, user.zone)
under_roles = lambda user, roles: user.active and check_user_of_roles(user.id, roles, user.zone)
granted_specs = lambda user, spec: user.active and check_user_at_spec(user.id, spec, user.zone)
granted_roles = lambda user, role: user.active and check_user_at_role(user.id, role, user.zone)

is_under_specs = under_specs
is_under_roles = under_roles
is_granted_specs = granted_specs
is_granted_roles = granted_roles

MODULE = ACCOUNTING
JSON_ROLE = json_role(MODULE)
JSON_ACCOUNT = json_account(MODULE)
YAML_TRANSACTION = yaml_transaction(MODULE)
YAML_REPORT = yaml_report(MODULE)
YAML_RICH = yaml_rich(MODULE)

load_roles = lambda: load_data(JSON_ROLE)
load_accounts = lambda: load_data(JSON_ACCOUNT)

roles_lst = lambda json=None: get_roles(MODULE, json if json else load_roles())
specs_lst = lambda json=None: get_specs(MODULE, json if json else load_roles())
roles_specs_lst = lambda json=None: [roles_lst(json), specs_lst(json)]

specs_inc_roles = lambda data=None: [{'spec': s['id'], 'roles': s['roles']} for s in (data if data else roles_specs_lst())[1]]
specs_roles_cls = lambda data=None: [DbSpecrole(spec=x['spec'], role=y) for x in specs_inc_roles(data) for y in x['roles']]

roles_cls = lambda data=None: [DbRole(**r) for r in (data if data else roles_specs_lst())[0]]
specs_cls = lambda data=None: [DbSpec(**s) for s in (data if data else roles_specs_lst())[1]]
roles_specs_cls = lambda data=None: (roles_cls(data), specs_cls(data))

role_and_spec_models = roles_specs_cls
specrole_pair_models = specs_roles_cls

account_groups = lambda: get_groups(MODULE, load_accounts())

groups_data = lambda: groups_scalar_data(account_groups())
roots_data = lambda: roots_scalar_data(account_groups())
accounts_data = lambda: accounts_scalar_data(account_groups())

account_group_models = lambda: [DbGroup(**r) for r in groups_data()]
accounts_root_models = lambda: [DbRoot(**r) for r in roots_data()]
plain_account_models = lambda: [DbAccount(**r) for r in accounts_data()]

dicts_userspecs = lambda us: [{'user': us.user, 'spec': x} for x in us.specs]
dicts_userroles = lambda ur: [{'user': ur.user, 'role': x} for x in ur.roles]

execmany_uni_model = lambda model, BuildModel: prepare_model(model, BuildModel, DbUni)
execmany_userspec_model = lambda model: DbUni(user=model.user, array=dicts_userspecs(model))
execmany_userrole_model = lambda model: DbUni(user=model.user, array=dicts_userroles(model))
execmany_accountitem_model = lambda model: DbUni(array=dicts_items(model))

dicts_specs = lambda specs: prepare_model(dicts(specs), DbSpec, DbUni)
dicts_roles = lambda roles: prepare_model(dicts(roles), DbRole, DbUni)
dicts_specroles = lambda specroles: prepare_model(dicts(specroles), DbSpecrole, DbUni)
dicts_accounts = lambda accounts: prepare_model(dicts(accounts), DbAccount, DbUni)
dicts_groups = lambda groups: prepare_model(dicts(groups), DbGroup, DbUni)
dicts_roots = lambda roots: prepare_model(dicts(roots), DbRoot, DbUni)

## INIT BEGIN

try:
  this = sys.modules[__name__]
  add_models_from_yaml(this)
  add_consts_from_yaml(this)
  add_consts_from_yaml(this, 'dbase.yaml') ## module_dbase
  add_consts_from_yaml(this, 'access.yaml') ## module_access
  create_dbase_functions(module_dbase[ADMIN])
  create_dbase_functions(module_dbase[ACCOUNTING])
  app_consts = data_load_from_yaml_file()[PARAMS]
except:
  print('Literp environment required, program exits')
  sys.exit()

## INIT END

token_expire_minutes = app_consts.setdefault('token_expire_minutes', token_expire_minutes)
NOINIT = app_consts.get('NOINIT')

login_user = select_check_login_user
working_login_user = select_working_login_user
system_moderator = select_system_moderator
system_admin = select_system_admin
zone_admin = select_zone_admin
zone_admin_or_very_user = select_zone_admin_or_very_user
system_moderator_or_zone_admin = select_system_moderator_or_zone_admin
system_moderator_or_zone_admin_or_very_user = select_system_moderator_or_zone_admin_or_very_user

## BASIC IO

def dump_database_tables(zoneidn: str, access_token: str) -> dict:
  ok, x, x = user_is_zone_admin(access_token, zoneidn)
  if not ok: return error_unexpect(f'EXPORT TABLES: {ROLE_ZONE_ADMIN}')
  return export_database_tables(zoneidn)

def dump_zone_database(zoneidn: str, table: str, access_token: str, idr: list=[]) -> dict:
  ok, x, x = user_is_zone_admin(access_token, zoneidn)
  if not ok: return error_unexpect(f'EXPORT DATABASE: {ROLE_ZONE_ADMIN}')
  return export_zone_database(zoneidn, table, idr=idr)

def load_zone_database(csvdata: str, zoneidn: str, table: str, access_token: str) -> dict:
  ok, x, x = user_is_zone_admin(access_token, zoneidn)
  if not ok: return error_unexpect(f'IMPORT DATABASE: {ROLE_ZONE_ADMIN}')
  return import_zone_database(zoneidn, table, {'data': csvdata})

def init_admin_database(adminpass: str=DEFPASSWORD) -> dict:
  if NOINIT: return error_unexpect('NOINIT flag is set', 'Install')
  task = batch([create_admin_zones, create_admin_users])
  if je(task): return task
  owner = insert_zone(genesis_zone())
  if je(owner): return owner
  admin = insert_user(genesis_user(adminpass))
  if je(admin): return admin
  return dict_result([{'Zone':owner, 'User':admin}])

def init_zone_database(zoneid: int, access_token: str) -> dict:
  ok, x, x = user_is_system_admin(access_token)
  if not ok: return error_unexpect(f'INSTALL CLIENT DATABASE: {ROLE_ADMIN}')
  if get_zoneid(zoneid) in [ADMINZONE, None]: return error_database(ERR_INPUT)
  if client_port_not_allowed(zoneid): return error_database(ERR_BADZONEID)
  task = batch([
  create_zone_roles,
  create_zone_specs,
  create_zone_specroles,
  create_zone_userspecs,
  create_zone_userroles,
  create_zone_groups,
  create_zone_roots,
  create_zone_accounts,
  create_zone_subs,
  create_zone_items,
  create_zone_txs,
  ], zonedb(zoneid))
  if je(task): return task
  return dict_result([{}])

def init_accounting_database(zoneid: int, access_token: str) -> dict:
  ok, x, x = user_is_system_admin(access_token)
  if not ok: return error_unexpect(f'INSTALL MODULE DATABASE: {ROLE_ADMIN}')
  if get_zoneid(zoneid) in [ADMINZONE, None]: return error_database(ERR_INPUT)
  if not dbexist(zoneid): return errnodb()
  roles, specs = role_and_spec_models()
  specroles = specrole_pair_models()
  groups = account_group_models()
  roots = accounts_root_models()
  accounts = plain_account_models()
  task = insert_zone_roles(dicts_roles(roles), zoneid)
  if je(task): return task
  task = insert_zone_specs(dicts_specs(specs), zoneid)
  if je(task): return task
  task = insert_zone_specroles(dicts_specroles(specroles), zoneid)
  if je(task): return task
  task = insert_zone_groups(dicts_groups(groups), zoneid)
  if je(task): return task
  task = insert_zone_roots(dicts_roots(roots), zoneid)
  if je(task): return task
  task = insert_zone_accounts(dicts_accounts(accounts), zoneid)
  if je(task): return task
  return dict_result([{}])

## CREDENTIALS

def user_under_specs(access_token: str, specs: list) -> bool:
  user = get_current_user(access_token)
  return under_specs(user, specs)

def user_under_roles(access_token: str, roles: list) -> bool:
  user = get_current_user(access_token)
  return under_roles(user, roles)

def user_granted_spec(access_token: str, spec: int) -> bool:
  user = get_current_user(access_token)
  return granted_specs(user, spec)

def user_granted_role(access_token: str, role: int) -> bool:
  user = get_current_user(access_token)
  return granted_roles(user, role)

def user_is_under_specs(access_token: str, specs: list) -> (bool, int, int):
  user = get_current_user(access_token)
  return under_specs(user, specs), user.id, user.zone

def user_is_under_roles(access_token: str, roles: list) -> (bool, int, int):
  user = get_current_user(access_token)
  return under_roles(user, roles), user.id, user.zone

def user_is_working(access_token: str, addict=None) -> (bool, int, int):
  user = get_current_user(access_token)
  return user.found, user.id, user.zone

def user_is_system_admin(access_token: str, addict=None) -> (bool, int, int):
  user = get_current_user(access_token, system_admin)
  return user.found, user.id, user.zone

def user_is_system_moderator(access_token: str, addict=None) -> (bool, int, int):
  user = get_current_user(access_token, system_moderator)
  return user.found, user.id, user.zone

def user_is_zone_admin(access_token: str, zoneidn: str) -> (bool, int, int):
  user = get_current_user(access_token, zone_admin, {COL_ZONEIDN: zoneidn, COL_CONUSER: None})
  return user.found, user.id, user.zoneidn

def user_is_ones_admin(access_token: str, conuser: str) -> (bool, int, int):
  user = get_current_user(access_token, zone_admin, {COL_CONUSER: conuser, COL_ZONEIDN: None})
  return user.found, user.id, user.zoneidn

user_is_zone_admin_of = user_is_ones_admin

def user_is_zone_manager(access_token: str, zoneidn: str) -> (bool, int, int):
  user = get_current_user(access_token, system_moderator_or_zone_admin, {COL_ZONEIDN: zoneidn, COL_CONUSER: None})
  return user.found, user.id, user.zoneidn

def user_is_ones_manager(access_token: str, conuser: str) -> (bool, int, int):
  user = get_current_user(access_token, system_moderator_or_zone_admin, {COL_CONUSER: conuser, COL_ZONEIDN: None})
  return user.found, user.id, user.zoneidn

user_is_zone_manager_of = user_is_ones_manager

def user_can_controll(access_token: str, useridn: str) -> (bool, int, int):
  user = get_current_user(access_token, zone_admin_or_very_user, {COL_USERIDN: useridn, COL_ZONEIDN: None})
  return user.found, user.id, user.zoneidn

def user_can_access(access_token: str, useridn: str) -> (bool, int, int):
  user = get_current_user(access_token, system_moderator_or_zone_admin_or_very_user, {COL_USERIDN: useridn, COL_ZONEIDN: None})
  return user.found, user.id, user.zoneidn

## Derivatives
def user_is_zone_creator(access_token: str, zoneidn: str) -> (bool, int, int):
  return user_is_system_admin(access_token) if adminzone(zoneidn) else user_is_system_moderator(access_token)

def self_is_admin(access_token: str, addict=None) -> (bool, int, int):
  user = get_current_user(access_token)
  return user.zadmin, user.id, user.zoneidn

def self_is_manager(access_token: str, addict=None) -> (bool, int, int):
  user = get_current_user(access_token)
  return (user.zadmin or user.zone==ADMINZONE), user.id, user.zoneidn

def self_is_creator(access_token: str, addict=None) -> (bool, int, int):
  user = get_current_user(access_token)
  return (user.zone==ADMINZONE), user.id, user.zoneidn

## ACTIONS

def check_login(hpwd: str, idname: str) -> (bool, int, int):
  data = first_row(login_user(DbUser(id=integer(idname), name=idname, hpwd=hpwd)))
  return (True, data[COL_ID], data[COL_ZONE]) if data else (False, None, None)

def get_user(model: DbUser, task: Callable=working_login_user, addict: dict={}) -> dict:
  if addict:
    model = model.model_dump()
    model.update(addict)
    model = DbUser(**model)
  return first_row(task(model))

def get_current_user(access_token: str, task: Callable=working_login_user, addict: dict={}) -> User:
  credentials_exception = User(name=ERR_VALIDATES)
  other_fatal_exception = User(name=ERR_AUTHLOGIN)
  try:
    payload = jwt.decode(access_token, os.environ[ENV_SECRET], algorithms=[token_crypto_algorithm])
    username = payload.get(TOKENID)
    if not username:
      return credentials_exception
    user = get_user(DbUser(name=username), task, addict)
    if not user:
      return credentials_exception
    user = User(**user)
    user.found = True
    return user
  except JWTError:
    return credentials_exception
  except Exception:
    return other_fatal_exception

def authenticate_user(username: str, md5_password: str) -> dict:
  user = get_user(DbUser(name=username))
  if not user:
    return {ERROR: ERR_USERNAME}
  if not verify_password(md5_password, user[COL_PASS]):
    return {ERROR: ERR_USERPASS}
  return user

def verify_password(md5_password: str, sha256_password: str) -> bool:
  return sha(md5_password)==sha256_password

def create_access_token(data: dict, expires_delta: Optional[timedelta]=None, algorithm: str=token_crypto_algorithm, expire_minutes: int=token_expire_minutes) -> str:
  to_encode = data.copy()
  if expires_delta:
    expire = datetime.utcnow() + expires_delta
  else:
    expire = datetime.utcnow() + timedelta(minutes=expire_minutes)
  to_encode['exp'] = expire
  return jwt.encode(to_encode, os.environ[ENV_SECRET], algorithm=algorithm)

def login(username: str, md5_password: str) -> Token.model_dump:
  user = authenticate_user(username, md5_password)
  if user.get(ERROR):
    return {TOKEN: ERROR, TOKENTYPE: user[ERROR]}
  access_token_expires = timedelta(minutes=token_expire_minutes)
  access_token = create_access_token(
    data={TOKENID: user[COL_NAME]},
    expires_delta=access_token_expires,
    algorithm=token_crypto_algorithm,
    expire_minutes=token_expire_minutes)
  return Token(user=user[COL_NAME], id=user[COL_ID], zone=user[COL_ZONE], zadmin=user[COL_ZADM], access_token=access_token, token_type=BEARER).model_dump()

## MISC

def http_allowed_origins(url: str=cors_base_url) -> list:
  zones = existing_zones_list()
  addrs = base_origins(url, zones)
  olist = merge_list(addrs, cors_allowed_origins())
  lanbase = app_consts.get('cors_lan_url')
  wanbase = app_consts.get('cors_wan_url')
  lanbases = [] if not lanbase else base_origins(lanbase, zones)
  wanbases = [] if not wanbase else base_origins(wanbase, zones)
  return merge_list(olist, lanbases+wanbases)

def existing_zones_list() -> list:
  defzones = [port_for_admin, port_for_api]
  extzones = select_all_zone_ids()
  if resultset_is_empty(extzones): return defzones
  return merge_list(defzones, extzones[RESULT])

def get_params(jsondata: str) -> dict:
  if je(data:=param_load_from_request(jsondata)): raise ValueError(ERR_JSONDATA)
  return data[PARAMS]

## API BASIS

def hello() -> dict:
  return {MESSAGE: 'cool' if dbexist() else 'poor'}

def hello_zone(zoneid: int) -> dict:
  return {MESSAGE: 'great' if dbexist(zoneid) else 'sucks'}

def what_module(modules: dict, funcname: str) -> dict:
  return {MESSAGE: function_module(modules, funcname)}

def do_login(username: str, md5_password: str, response: Response) -> Token:
  res = login(username, md5_password)
  response.set_cookie(key=TOKEN, value=res[TOKEN])
  return res

def do_logout(response: Response) -> dict:
  response.set_cookie(key=TOKEN, value='', expires=0)
  return {MESSAGE: 'You are logged out'}

## API IO

def set_afunc(funcname: str, value: any, field: str='edata') -> bool:
  module = function_module2(module_access, funcname)
  if not module: return False
  dict_assign(module_access, f'{module}.{funcname}.{field}', value=value, add=True)
  return True

def update_afunc(field: str='edata') -> dict:
  data = load_yaml(f'{field}.yaml')[field]
  for f in data: set_afunc(f, data[f][field], field)
  return module_access

def sort_module_access():
  modules = app_consts.get('modules')
  for module in modules: dict_sort(module_access, module)

## DB BASIS

def wrapvals(model: DbTxs) -> list:
  data = model.data ## [model] list
  if (count:=len(data))<2: return False
  vals = []
  for i in range (count):
    data[i].uuid = model.uuid if i==0 else uid()
    data[i].tx = model.uuid
    data[i].dated = model.dated
    data[i].creator = model.creator
    vals.append(data[i])
  valdicts = dicts(vals) ## [{}] list
  if lds(valdicts, COL_DEBIT) != lds(valdicts, COL_CREDIT): return None
  return vals ## [model] list

def wraptx(model: DbTxs) -> dict:
  vals = wrapvals(model)
  if vals is False: raise(Exception(NOENTRIES))
  if vals is None: raise(Exception(NOBALANCE))
  model = DbUni(array=dicts(vals))
  return model

def bind_values(query: str, modelval: DbUni(), vfunc: Callable, vattr: str, sfunc: Callable=str_to_list, outdict: bool=False) -> tuple:
  values = sfunc(getattr(modelval, vattr))
  query = vfunc(query, values)
  return {'query': query, 'values': values} if outdict else (query, values)

## HTTP

def reload_edata(edata: dict=EDATA):
  for e in edata:
    globals()[e] = EDATA[e]
    setattr(this, e, EDATA[e])

def prepare_inputs(params: dict, passfunc: Callable=prepare_password) -> dict:
  passfunc(params, COL_PASS)
  passfunc(params, COL_OPWD)
  passfunc(params, COL_NPWD)
  return params

def prepare_params(params: dict, userid: int, quelibid: str=None, dbfuncid: str=None, modelid: str=None, moduleid: str=None, InfoModel: DbUni=None, infofunc: Callable=prepare_info) -> dict:
  params[COL_CREATOR] = userid
  params[COL_MODIFIER] = userid
  if modelid: params[JMODEL] = modelid
  if moduleid: params[JDBMOD] = moduleid
  if quelibid: params[JDBQUE] = quelibid
  if dbfuncid: params[JDFUNC] = dbfuncid
  params['query'] = get_rich_query(params)
  params['retquery'] = get_rich_retquery(params)
  params[COL_DATED] = parse_doc_date(params.get(COL_DATED))
  if infofunc and InfoModel: infofunc(params, COL_INFO, InfoModel)
  return params

def prepare_param_array(params: dict, userid: int) -> dict:
  if params.get(ARRAY):
    params[ARRAY] = [prepare_params(x, userid) for x in params[ARRAY]]
  return params

def prepare_jsondata(jsondata: str, back: bool=False, layer: int=3, jafarg: any=None):
  params = get_params(jsondata)
  default(params, JAFARG, jafarg)
  default(params, JMODEL, 'DbUni')
  default(params, JDBQUE, 'select')
  default(params, JDBMOD, 'accounting')
  default(params, JDFUNC, 'select_dict')
  default(params, JQUEID, callup(layer))
  default(params, COL_UUID, uid())
  if not back: return params
  return json.dumps(params)

def appdb(
  access_token,
  jsondata: str,
  modelid: str='DbUni',
  InfoModel: any=None,
  DelModel: any=None,
  pwdfunc: Callable=None,
  prefunc: Callable=None,
  delfunc: Callable=None,
  parfunc: Callable=get_idname,
  errfunc: Callable=error_unexpect,
  caller: str=None) -> dict: ## QueryIdName
  if not caller: caller = callup() ## FName
  model = get_model(caller, defval=modelid)
  afunc = get_afunc(caller, finval=do_none)
  erole = get_erole(caller)
  edata = get_edata(caller)
  qpath = get_qpath(caller)
  dfunc = get_dfunc(caller)
  build = get_build(caller)
  mfunc = get_mfunc(caller)
  dbfunc, valid, query = access_function(caller, model, dfunc)
  if not valid: return errfunc(f'{ERR_FUNCTION}: {caller}')
  pwdfunc = get_wfunc(caller, defval=pwdfunc)
  prefunc = get_ifunc(caller, defval=prefunc)
  parfunc = get_pfunc(caller, defval=parfunc)
  delfunc = get_bfunc(caller, defval=delfunc)
  DelModel = get_mdele(caller, defval=DelModel)
  InfoModel = get_minfo(caller, defval=InfoModel)
  access_token = get_token(caller, defval=access_token)
  prepare_inputs(params:=prepare_jsondata(jsondata), passfunc=pwdfunc or prepare_password)
  ok, userid, zoneid = afunc(access_token if not callable(access_token) else access_token(params), edata or (parfunc(params) if parfunc else None))
  if not ok: return errfunc(f'{this.MSG.get(caller) or to_upper(caller)}: {erole}{SPACE+str(edata) if edata else ""}')
  if checkonly(params): return dict_result([{}])
  prepare_params(params, userid, InfoModel=InfoModel, infofunc=prefunc)
  prepare_param_array(params, userid) ## prepare for ExecuteMany data action
  if (bad:=get_cfunc(caller)) and bad(params.get(get_cattr(caller))): return errfunc(get_cemsg(caller))
  if delfunc and DelModel: delfunc(DelModel(name=get_idname(params)), zoneid)
  if mfunc: return dbfunc(mfunc(params.get(ARRAY), build, DbUni), zoneid)
  values = model(**params)
  if up:=get_ufunc(caller): up(values)
  if pm:=get_mprep(caller): values = pm(values)
  query, values = bind_values(query, values, vfunc, get_vattr(caller)) if (vfunc:=get_vfunc(caller)) else (query, values)
  return dbfunc(values, zoneid, query=query)

reload_edata()
