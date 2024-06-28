import json
from stix_shifter_utils.modules.base.stix_transmission.base_json_sync_connector import BaseJsonSyncConnector
from .api_client import APIClient
from stix_shifter_utils.utils.error_response import ErrorResponder
from stix_shifter_utils.utils import logger
from requests.exceptions import ConnectionError


class QueryException(Exception):
    pass

class Connector(BaseJsonSyncConnector):
    init_error = None
    logger = logger.set_logger(__name__)
    PROVIDER = 'CrowdStrike'
    IDS_LIMIT = 500

    def __init__(self, connection, configuration):
        """Initialization.
        :param connection: dict, connection dict
        :param configuration: dict,config dict"""
        self.connector = __name__.split('.')[1]
        
        try:
            self.api_client = APIClient(connection, configuration)
            self.result_limit = Connector.get_result_limit(connection)

        except Exception as ex:
            self.init_error = ex

    def _handle_errors(self, response, return_obj):
        """Handling API error response
        :param response: response for the API
        :param return_obj: dict, response for the API call with status
        """
        response_code = response.code
        response_txt = response.read().decode('utf-8')
        response_type = response.headers.get('Content-Type')
        response_dict = {}

        if 200 <= response_code < 300:
            return_obj['success'] = True
            return_obj['data'] = response_txt
            return return_obj
        elif response_code >= 400:
            if response_type == 'application/json':
                error_response = json.loads(response_txt)
                response_dict['type'] = 'ValidationError'
                response_dict['message'] = error_response['errors'][0]['message']
                ErrorResponder.fill_error(return_obj, response_dict, ['message'], connector=self.connector)
                raise QueryException(return_obj)
            elif response_type == 'text/html':
                error = ConnectionError(f'Error connecting the datasource: {response_txt}')
                ErrorResponder.fill_error(return_obj, response_dict, error=error, connector=self.connector)
                raise QueryException(return_obj)
            else:
                raise Exception(response_txt)

    
    async def ping_connection(self):
        response_txt = None
        return_obj = {}
        response_dict = {}
        try:
            response = await self.api_client.ping_box()
            response_code = response.code
            response_txt = response.read().decode('utf-8')
            response_type = response.headers.get('Content-Type')
            if 199 < response_code < 300:
                return_obj['success'] = True
            elif response_code == 401:
                if response_type == 'application/json':
                    error_response = json.loads(response_txt)
                    response_dict['type'] = 'AuthenticationError'
                    response_dict['message'] = error_response['errors'][0]['message']
                    self.logger.error('Error connecting the Crowdstrike datasource: ' + str(error_response))
                    ErrorResponder.fill_error(return_obj, response_dict, ['message'], connector=self.connector)
                else:
                    raise Exception(response_txt)
            elif response_code == 400:
                if response_type == 'application/json':
                    error_response = json.loads(response_txt)
                    response_dict['type'] = 'ValidationError'
                    response_dict['message'] = error_response['errors'][0]['message']
                    self.logger.error('Error connecting the Crowdstrike datasource: ' + str(error_response))
                    ErrorResponder.fill_error(return_obj, response_dict, ['message'], connector=self.connector)
                else:
                    raise Exception(response_txt)
            else:
                if response_type == 'application/json':
                    response_error_ping = json.loads(response_txt)
                    response_dict = response_error_ping['errors'][0]
                    ErrorResponder.fill_error(return_obj, response_dict, ['message'], connector=self.connector)
                elif response_type == 'text/html':
                    error = ConnectionError(f'Error connecting the datasource: {response_txt}')
                    ErrorResponder.fill_error(return_obj, response_dict, error=error, connector=self.connector)
                else:
                    raise Exception(response_txt)
        except Exception as e:
            if response_txt is not None:
                ErrorResponder.fill_error(return_obj, message='unexpected exception: ' + str(response_txt), connector=self.connector)
                self.logger.error('Can not parse response Crowdstrike error: ' + str(response_txt))
            else:
                raise e

        return return_obj

    async def send_info_request_and_handle_errors(self, ids_lst):
        return_obj = dict()
        response = await self.api_client.get_detections_info(ids_lst)
        return_obj = self._handle_errors(response, return_obj)
        response_json = json.loads(return_obj["data"])
        return_obj['data'] = response_json['resources']

        return return_obj

    async def handle_detection_info_request(self, ids):
        ids = [ids[x:x + self.IDS_LIMIT] for x in range(0, len(ids), self.IDS_LIMIT)]
        ids_lst = ids.pop(0)
        return_obj = await self.send_info_request_and_handle_errors(ids_lst)

        for ids_lst in ids:
            curr_obj = await self.send_info_request_and_handle_errors(ids_lst)
            return_obj['data'].extend(curr_obj['data'])
        return return_obj

    @staticmethod
    def get_result_limit(connection):
        default_result_limit = Connector.IDS_LIMIT
        if 'options' in connection:
            return connection['options'].get('result_limit', default_result_limit)
        return default_result_limit

    async def create_results_connection(self, query, offset, length):
        """"built the response object
        :param query: str, search_id
        :param offset: int,offset value
        :param length: int,length value"""
        result_limit = offset + length
        ids_obj = dict()
        return_obj = dict()

        try:
            if self.init_error:
                raise self.init_error

            response = await self.api_client.get_alert_IDs(query, result_limit)
            self._handle_errors(response, ids_obj)
            response_json = json.loads(ids_obj["data"])
            ids_obj['ids'] = response_json.get('resources')

            if ids_obj['ids']:  # There are not detections that match the filter arg
                return_obj = await self.handle_detection_info_request(ids_obj['ids'])

            if not return_obj.get('success'):
                if(not return_obj.get('data')):
                    return_obj['data'] = {}
                return_obj['success'] = True
            return return_obj
        except QueryException as ex:
            return ex.args[0]
        except Exception as ex:
            error_dict = {}
            error_dict['type'] = 'AttributeError'
            error_dict['message'] = 'Error while parsing API response: ' + str(ex)
            ErrorResponder.fill_error(return_obj, error_dict, ['message'], connector=self.connector)
            self.logger.error('Unexpected exception from Crowdstrike datasource: ' + str(ex))

            return return_obj
