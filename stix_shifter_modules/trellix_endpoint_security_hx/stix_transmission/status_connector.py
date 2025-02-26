from stix_shifter_utils.modules.base.stix_transmission.base_status_connector import BaseStatusConnector
from stix_shifter_utils.modules.base.stix_transmission.base_status_connector import Status
from enum import Enum
from stix_shifter_utils.utils.error_response import ErrorResponder
from stix_shifter_utils.utils import logger
import json


class UnsupportedHostSetException(Exception):
    pass


class TrellixStatus(Enum):
    RUNNING = 'RUNNING'
    COMPLETED = 'COMPLETED'


class StatusConnector(BaseStatusConnector):
    def __init__(self, api_client):
        self.api_client = api_client
        self.logger = logger.set_logger(__name__)
        self.connector = __name__.split('.')[1]

    @staticmethod
    def __get_status(status):
        """
        Return the status of the search id
        :param status: str,
        :return: str
        """
        switcher = {
            TrellixStatus.COMPLETED.value: Status.COMPLETED,
            TrellixStatus.RUNNING.value: Status.RUNNING,
        }
        return switcher.get(status).value

    async def create_status_connection(self, search_id):
        """
        Fetching the progress and the status of the search id
        :param search_id: str
        :return: return_obj, dict
        """
        return_obj = {}
        try:
            if not self.api_client.headers.get('X-FeApi-Token'):
                token_obj = await self.__get_token()
                if token_obj:
                    return token_obj
            response_code, response_content = await self.make_api_call(search_id.split(":")[0])
            if response_code == 200:
                return_obj = self.fetch_status_and_progress(return_obj, response_content)
            else:
                return_obj = await self.handle_api_exception(response_code, response_content)

        except UnsupportedHostSetException as ex:
            return_obj = await self.handle_api_exception(100, f'The input query is not '
                                                              f'supported for the host set {str(ex)}')

        except Exception as err:
            self.logger.error(f'Error when getting search status in Trellix Endpoint Security: {err}')
            return_obj = await self.handle_api_exception(None, str(err))

        await self.api_client.delete_token()
        return return_obj

    async def make_api_call(self, search_id):
        """
        Make API call to fetch the status of search id
        :return:
        """
        response = await self.api_client.get_search_status(search_id)
        response_code = response.code
        response_content = response.read().decode('utf-8')
        return response_code, response_content

    async def handle_api_exception(self, code, response_data):
        """
        create the exception response
        :param code, int
        :param response_data, dict
        :return: return_obj, dict
        """
        return_obj = {}
        try:
            response_data = json.loads(response_data)
            if response_data.get('details', []):
                message = response_data['details'][0]['message']
            else:
                message = response_data.get('message')
        except json.JSONDecodeError:
            message = response_data
        response_dict = {'code': code, 'message': message}
        ErrorResponder.fill_error(return_obj, response_dict, ['message'], connector=self.connector)
        return return_obj

    async def __get_token(self):
        """
        Generate a new API token
        :return:
        """
        return_obj = {}
        response = await self.api_client.generate_token()
        if response.code == 204 and response.headers.get('X-FeApi-Token'):
            self.api_client.headers['X-FeApi-Token'] = response.headers['X-FeApi-Token']
            if self.api_client.headers.get('Authorization'):
                self.api_client.headers.pop('Authorization')
        else:
            return_obj = await self.handle_api_exception(response.code, response.read().decode('utf-8'))
        return return_obj

    def fetch_status_and_progress(self, return_obj, response_content):
        """
        Find the status and calculate the progress
        :param return_obj:
        :param response_content:
        :return: return_obj, dict
        """
        return_obj['success'] = True
        response_content = json.loads(response_content)
        return_obj['status'] = StatusConnector.__get_status("RUNNING")
        return_obj['progress'] = 0

        data = response_content.get("data", {})
        if data:
            host_count = data.get("stats", {}).get("hosts", 0)
            search_completed_count = data.get("stats", {}).get("running_state", {}).get('COMPLETE')
            if host_count > 0:
                return_obj['progress'] = int(search_completed_count / host_count * 100)
            else:
                raise UnsupportedHostSetException(data.get('host_set').get('name'))
            if return_obj['progress'] >= self.api_client.progress_threshold:
                return_obj['progress'] = 100
                return_obj['status'] = StatusConnector.__get_status("COMPLETED")

        return return_obj
