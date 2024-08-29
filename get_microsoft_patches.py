import contextlib
import datetime
import json
import re
import uuid

from bs4 import BeautifulSoup
import requests

try:
    from urllib.parse import quote, urlencode, urlparse
    from urllib.request import Request, urlopen, urlretrieve
except ImportError:  # Python 2
    from urllib import quote, urlencode, urlretrieve
    from urllib2 import Request, urlopen
    from urlparse import urlparse

CATALOG_URL = 'https://www.catalog.update.microsoft.com/'
UPDATE_URL = ""
DOWNLOAD_PATTERN = re.compile(r'\[(\d*)\]\.url = [\"\'](https?://catalog\.s\.download\.windowsupdate\.com/[^\'\"]*)')
#DOWNLOAD_PATTERN = re.compile(r'https:\/\/catalog\.s\.download\.windowsupdate\.com\/d\/msdownload\/update\/software\/secu\/\d{4}\/\d{2}\/windows10\.0-kb\d+-x64_[0-9a-f]+\.\w{3}')
PRODUCT_SPLIT_PATTERN = re.compile(r',(?=[^\s])')


@contextlib.contextmanager
def fetch_url(url, data=None, headers=None):
    # Python 2 does not have urlopen as a contextmanager, just make our own
    req = Request(url, data=data, headers=headers)
    resp = urlopen(req)
    try:
        yield resp
    finally:
        resp.close()


class WUDownloadInfo:

    def __init__(self, download_id, url, raw):
        """
        Contains information about an individual download link for an update. An update might have multiple download
        links available and this keeps track of the metadata for each of them.

        :param download_id: The ID that relates to the download URL.
        :param url: The download URL for this entry.
        :param raw: The raw response text of the downloads page.
        """
        self.url = url
        self.digest = None
        self.architectures = None
        self.languages = None
        self.long_languages = None
        self.file_name = None

        attribute_map = {
            'digest': 'digest',
            'architectures': 'architectures',
            'languages': 'languages',
            'long_languages': 'longLanguages',
            'file_name': 'fileName',
        }
        for attrib_name, raw_name in attribute_map.items():
            regex_pattern = r"\[%s]\.%s = ['\"]([\w\-\.=+\/\(\) ]*)['\"];" \
                            % (re.escape(download_id), re.escape(raw_name))
            regex_match = re.search(regex_pattern, raw)
            if regex_match:
                setattr(self, attrib_name, regex_match.group(1))

    def __str__(self):
        return "%s - %s" % (self.file_name or "unknown", self.long_languages or "unknown language")


class WindowsUpdate:

    def __init__(self, raw_element):
        """
        Stores information about a Windows Update entry.

        :param raw_element: The raw XHTML element that has been parsed by BeautifulSoup4.
        """
        cells = raw_element.find_all('td')
        self.title = cells[1].get_text().strip()

        # Split , if there is no space ahead.
        products = cells[2].get_text().strip()
        self.products = list(filter(None, re.split(PRODUCT_SPLIT_PATTERN, products)))
        self.classification =  str(cells[3].get_text()).strip()
        self.last_updated = datetime.datetime.strptime(cells[4].get_text().strip(), '%m/%d/%Y')
        self.version = cells[5].get_text().strip()
        self.size = cells[6].find_all('span')[0].get_text().strip()
        self.id = uuid.UUID(cells[7].find('input').attrs['id'])
        self._details = None
        self._architecture = None
        self._description = None
        self._download_urls = None
        self._kb_numbers = None
        self._more_information = None
        self._msrc_number = None
        self._msrc_severity = None
        self._support_url = None
        self._is_installable = None
        self._languages = None
        self._requires_connectivity = None
        self._requires_user_input = None
        self._requires_restart = None
        self._superseeds = None 

    @property
    def product(self):
        """ The product name of the update. """
        return self.products[0]
    @ property
    def classifications(self):
        """ The classification of the update. """
        return self.classification
    @property
    def architecture(self):
        """ The architecture of the update. """
        if not self._architecture:
            details = self.get_details()
            raw_arch = details.find(id='ScopedViewHandler_labelArchitecture_Separator')
            self._architecture = raw_arch.next_sibling.strip()

        return self._architecture
   
    @property
    def languages(self):
        """ The languages of the update. """
        details = self.get_details()
        raw_lang = details.find(id='ScopedViewHandler_labelSupportedLanguages_Separator')
        self._languages = raw_lang.next_sibling.strip()

        return self._languages
    
    @property
    def superseeds(self):
        """ The superseeds of the update. """
        details = self.get_details()
        superseeds_list = []
        super_sedes_info = details.find(id='supersedesInfo')
        if super_sedes_info:
            superseeds_text = super_sedes_info.get_text().strip()
            if superseeds_text:
                superseeds_text = superseeds_text.replace("\n\r\n", " ")
                superseeds_list = superseeds_text.split("\n")
                if superseeds_list:
                    superseeds_list = [x.strip() for x in superseeds_list]
                    superseeds_list = [x.replace("\r","") for x in superseeds_list if x]
            self._superseeds = superseeds_list if superseeds_list else superseeds_text
        else:
            self._superseeds = "None"

        return self._superseeds

    @property
    def descriptions(self):
        """ The description of the update. """
        if not self._description:
            details = self.get_details()
            self._description = details.find(id='ScopedViewHandler_desc').get_text()

        return self._description

    @property
    def download_url(self):
        """ The download URL of the update, will fail if the update contains multiple packages. """
        download_urls = self.get_download_urls()

        # if len(download_urls) != 1:
        #     raise ValueError("Expecting only 1 download link for '%s', received %d. Use get_download_urls() and "
        #                      "filter it based on your criteria." % (str(self), len(download_urls)))
        if len(download_urls) == 0:
            return None
        return download_urls

    @property
    def is_installable(self):
        if self._is_installable is None:
            details = self.get_details()
            uninstall_desc = details.find(id='ScopedViewHandler_labelUninstallNotes_Separator').find_next_sibling('div').get_text()
            if "can be removed" in uninstall_desc:
                self._is_installable = True
            else:
                self._is_installable = False
            return self._is_installable
        else:
             return self._is_installable
        
    #ScopedViewHandler_labelInstallRequiresConnectivity_Separator
    @property
    def requires_connectivity(self):
        if self._requires_connectivity is None:
            details = self.get_details()
            raw_info = details.find(id='ScopedViewHandler_connectivity').get_text()
            self._requires_connectivity = raw_info
        return self._requires_connectivity

    #ScopedViewHandler_userInput
    @property
    def requires_user_input(self):
        if self._requires_user_input is None:
            details = self.get_details()
            raw_info = details.find(id='ScopedViewHandler_userInput').get_text()
            self._requires_user_input = raw_info
        return self._requires_user_input

        
    @property
    def kb_numbers(self):
        """ A list of KB article numbers that apply to the update. """
        if self._kb_numbers is None:
            details = self.get_details()
            raw_kb = details.find(id='ScopedViewHandler_labelKBArticle_Separator')

            # If no KB's apply then the value will be n/a. Technically an update can have multiple KBs but I have
            # not been able to find an example of this so cannot test that scenario.
            if raw_kb and raw_kb.next_sibling.strip():
                self._kb_numbers = [int(n.strip()) for n in list(raw_kb.next_siblings) if n.strip().lower() != 'n/a']

        return self._kb_numbers

    @property
    def more_information(self):
        """ Typically the URL of the KB article for the update but it can be anything. """
        if self._more_information is None:
            details = self.get_details()
            raw_info = details.find(id='ScopedViewHandler_labelMoreInfo_Separator')
            self._more_information = list(raw_info.next_siblings)[1].get_text().strip()

        return self._more_information


    @property
    def msrc_number(self):
        """ The MSRC Number for the update, set to n/a if not defined. """
        if self._msrc_number is None:
            details = self.get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSecurityBulliten_Separator')
            if raw_info and ("n/a" not in  raw_info.next_sibling) and len(list(raw_info.next_sibling)) > 1:
                self._msrc_number = list(raw_info.next_siblings)[-1].get_text().strip()
            
        return self._msrc_number

    @property
    def msrc_severity(self):
        """ THe MSRC severity level for the update, set to Unspecified if not defined. """
        if self._msrc_severity is None:
            details = self.get_details()
            if details.find(id='ScopedViewHandler_msrcSeverity'):
                self._msrc_severity = details.find(id='ScopedViewHandler_msrcSeverity').get_text().strip()

        return self._msrc_severity

    @property
    def support_url(self):
        """ The support URL for the update. """
        if self._support_url is None:
            details = self.get_details()
            raw_info = details.find(id='ScopedViewHandler_labelSupportUrl_Separator')
            self._support_url = list(raw_info.next_siblings)[1].get_text().strip()

        return self._support_url

    #ScopedViewHandler_rebootBehavior
    @property
    def requires_restart(self):
        if self._requires_restart is None:
            details = self.get_details()
            raw_info = details.find(id='ScopedViewHandler_rebootBehavior').get_text()
            self._requires_restart = raw_info
        return self._requires_restart

    def get_download_urls(self):
        """
        Get a list of WUDownloadInfo objects for the current update. These objects contain the download URL for all the
        packages inside the update.
        """
        if self._download_urls is None:
            update_ids = json.dumps({
                'size': 0,
                'updateID': str(self.id),
                'uidInfo': str(self.id),
            })
            data = urlencode({'updateIDs': '[%s]' % update_ids}).encode('utf-8')

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            with fetch_url('%s/DownloadDialog.aspx' % CATALOG_URL, data=data, headers=headers) as resp:
                resp_text = resp.read().decode('utf-8').strip()

            link_matches = re.findall(DOWNLOAD_PATTERN, resp_text)
        
            if len(link_matches) == 0:
                raise ValueError("Failed to find any download links for '%s'" % str(self))

            download_urls = []
            for download_id, url in link_matches:
                download_urls.append(WUDownloadInfo(download_id, url, resp_text))
            
            self._download_urls = download_urls
            

        return self._download_urls

    def get_details(self):
        if not self._details:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            with fetch_url('%s/ScopedViewInline.aspx?updateid=%s' % (CATALOG_URL, str(self.id)),
                           headers=headers) as resp:
                resp_text = resp.read().decode('utf-8').strip()
            self._details = BeautifulSoup(resp_text, 'html.parser')

        return self._details

    def __str__(self):
        return print(self.get_details())


def find_updates(search, all_updates=True, sort=None, sort_reverse=False, data=None):
    try:
        """
        Generator function that yields WindowsUpdate objects for each update found on the Microsoft Update catalog.
        Yields a list of updates from the Microsoft Update catalog. These updates can then be downloaded locally using the
        .download(path) function.

        :param search: The search string used when searching the update catalog.
        :param all_updates: Set to True to continue to search on all pages and not just the first 25. This can dramatically
            increase the runtime of the script so use with caution.
        :param sort: The field name as seen in the update catalog GUI to sort by. Setting this will result in 1 more call
            to the catalog URL.
        :param sort_reverse: Reverse the sort after initially sorting it. Setting this will result in 1 more call after
            the sort call to the catalog URL.
        :param data: Data to post to the request, used when getting all pages
        :return: Yields the WindowsUpdate objects found.
        """

        search_safe = quote(search)
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        if data:
            data = urlencode(data).encode('utf-8')

        url = '%s/Search.aspx?q=%s' % (CATALOG_URL, search_safe)
        with fetch_url(url, data=data, headers=headers) as resp:
            resp_text = resp.read().decode('utf-8').strip()

        catalog = BeautifulSoup(resp_text, 'html.parser')
    
        # If we need to perform an action (like sorting or next page) we need to add these 4 fields that are based on the
        # original response received.
        def build_action_data(action):
            data = {
                '__EVENTTARGET': action,
            }
            for field in ['__EVENTARGUMENT', '__EVENTVALIDATION', '__VIEWSTATE', '__VIEWSTATEGENERATOR']:
                element = catalog.find(id=field)
                if element:
                    data[field] = element.attrs['value']

            return data
        if not catalog.find(id='ctl00_catalogBody_updateMatches'):
            raise ValueError("Failed to find any updates for '%s'" % search)
        raw_updates = catalog.find(id='ctl00_catalogBody_updateMatches').find_all('tr')
        headers = raw_updates[0]  # The first entry in the table are the headers which we may use for sorting.

        if sort:
            # Lookup the header click JS targets based on the header name to sort.
            header_links = headers.find_all('a')
            event_targets = dict((l.find('span').get_text(), l.attrs['id'].replace('_', '$')) for l in header_links)
            data = build_action_data(event_targets[sort])

            sort = sort if sort_reverse else None  # If we want to sort descending we need to sort it again.
            for update in find_updates(search, all_updates, sort=sort, data=data):
                yield update
            return

        for u in raw_updates[1:]:
            yield WindowsUpdate(u)

        # ctl00_catalogBody_nextPage is set when there are no more updates to retrieve.
        last_page = catalog.find(id='ctl00_catalogBody_nextPage')
        if not last_page and all_updates:
            data = build_action_data('ctl00$catalogBody$nextPageLinkText')
            for update in find_updates(search, True, data=data):
                yield update
    
    except Exception as e:
        print("Exception occured in main function while fetching updates from Microsoft Catalogue: %s" % str(e))
        return []

def find_microsoft_catelogue_updates(serach):
    try:
        updates = {
        "updates": []
        }
        super_seeds_list = []
        
        for update in find_updates(search, all_updates=True, sort=None, sort_reverse=False):

            update_details = {
                "kb": update.kb_numbers,
                "title": update.title,
                "update_id": str(update.id),
                "kb_number": update.kb_numbers,
                "version": update.version,
                "last_updated": str(update.last_updated),
                "classification" : update.classifications,
                "languages": update.languages,
                "superseeds": update.superseeds,
                "msrc_number": update.msrc_number,
                "msrc_severity": update.msrc_severity,
                "products_applicable": update.product.lower() if update.product else "",
                "architecture": update.architecture,
                "uninstallable" : update.is_installable,
                "requires_connectivity": update.requires_connectivity,
                "requires_user_input": update.requires_user_input,
                "requires_restart": update.requires_restart,
                "update_size": update.size,
                "more_info" : update.more_information,
                "description": update.descriptions,
                "support_url": update.support_url
            }
            download_urls = []
            for download in update.get_download_urls():
                download_urls.append({
                    "file_name": urlparse(download.url).path.split('/')[-1],
                    "download_link": str(download.url)
                })
            
            update_details["download_urls"] = download_urls
            if update_details["title"]:
                if update_details['superseeds']:
                    super_seeds_list.append(update_details['superseeds'])
        
            updates["updates"].append(update_details)
        
        if updates.get("updates"):
            filtered_updates = {
                "updates": []
            }
            
            filtered_updates["updates"] = updates["updates"]
            applicable_updates = []
            for update in filtered_updates["updates"]:
                super_seed_found = False
                for super_seed in super_seeds_list:
                    if update["title"] == super_seed:
                        super_seed_found = True
                        break
                if not super_seed_found :
                    applicable_updates.append(update)

            filtered_updates["updates"] = applicable_updates

            return filtered_updates.get("updates")

        else:
            return None
        
    except Exception as e:
        print("Exception occured while fetching updates from Microsoft Catalogue: %s" % str(e))
        return None

def convert_bytes_to_human_readable(size_bytes, threshold_gb=1):
    # Convert bytes to gigabytes
    size_gb = size_bytes / (1024 ** 3)

    if size_gb >= threshold_gb:
        return f"{size_gb:.2f} GB"
    else:
        # Convert bytes to megabytes
        size_mb = size_bytes / (1024 ** 2)
        return f"{size_mb:.2f} MB"
    
def get_update_size(download_details):
    try:
        file_size = 0
        for download_link_detail in download_details:
            file_size += int(download_link_detail.get("size"))
        #convert to gb if more than 1 gb else give in mb
        return convert_bytes_to_human_readable(file_size)
    except:
        return "N/A"

def get_version_number(download_details):
    try:
        for download_link_detail in download_details:
            return download_link_detail.get("version")
    except:
        return None

def get_last_updated(download_details):
    try:
        for download_link_detail in download_details:
            return download_link_detail.get("datePublished")
    except:
        return None
    
def get_architecture(download_details):
    try:
        for download_link_detail in download_details:
            if "64" in download_link_detail.get("name"):
                return "x64"
            elif "32" in download_link_detail.get("name") or ("86" in download_link_detail.get("name") and "64" not in download_link_detail.get("name")):
                return "x86"
    except:
        return None
    
def get_kb_number(download_details):
    try:
        for download_link_detail in download_details:
            file_name = download_link_detail.get("name").lower()
            if "kb" in file_name:
                #get the kb number
                kb_number = ""
                kb_start_index = file_name.index("kb") + 2
                for i in range(kb_start_index, len(file_name)):
                    if file_name[i].isdigit():
                        kb_number += file_name[i]
                    else:
                        break
                return kb_number
        return None
    except:
        return None

def get_microsoft_windows_product_update(download_page_link):
    try:

        user_agent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)"
        headers = {"User-Agent": user_agent}
        download_page_content = requests.get(download_page_link, headers=headers).content
        # Parse the HTML content
        soup = BeautifulSoup(download_page_content, 'html.parser')
        update_details = []

        #get the actual link from the page
        #<link href="https://www.microsoft.com/en-us/download/details.aspx?id=105652" rel="canonical"/>
        canonical_link = soup.find("link", {"rel": "canonical"})
        actual_download_link = canonical_link.get("href")
        

        languages = [{
            "cultureCode": "en-us",
            "name": "English"
        }]

        #find the dict in <script>window.__DLCDetails__=
        info_dict = soup.find_all("script")
        parsed_dict = {}

        # commented this for now as it is not required
        # if ">window.__DLCDetails__=" in str(info_dict):
        #     if "downloadFile" in str(info_dict):
        #         info_dict = str(info_dict).split(">window.__DLCDetails__=")[1].split("</script>")[0]
        #         info_dict = info_dict.replace("\\", "")
        #         info_dict = info_dict.replace("\n", "")
        #         info_dict = info_dict.replace("\t", "")
        #         info_dict = info_dict.replace("\r", "")

        #         #localeDropdown
        #         locale_dropdown = info_dict[info_dict.index("localeDropdown")-1:]
        #         locale_dropdown = locale_dropdown[:locale_dropdown.index(r'],')+1]
        #         locale_dropdown = json.loads("{"+locale_dropdown+"}")
        #         languages = locale_dropdown["localeDropdown"]
        

        for language in languages:
            language_code = language["cultureCode"]
            language_name = language["name"]
            
            #https://www.microsoft.com/en-us/download/details.aspx?id=105652
            #replace the language code in the link

            # updated_link = actual_download_link.replace("en-us", language_code)
            
            # download_page_content = requests.get(updated_link, headers=headers).content
            
            # # Parse the HTML content
            # new_soup = BeautifulSoup(download_page_content, 'html.parser')
        
            #find the dict in <script>window.__DLCDetails__=
            # info_dict = new_soup.find_all("script")

            parsed_dict = {}
            if ">window.__DLCDetails__=" in str(info_dict):

                if "downloadFile" in str(info_dict):
                    info_dict = str(info_dict).split(">window.__DLCDetails__=")[1].split("</script>")[0]
                    info_dict = info_dict.replace("\\", "")
                    info_dict = info_dict.replace("\n", "")
                    info_dict = info_dict.replace("\t", "")
                    info_dict = info_dict.replace("\r", "")
                    
                    download_file = info_dict[info_dict.index("downloadFile")-1:]
                    download_file = download_file[:download_file.index("]")+1]
                    download_file = json.loads("{"+download_file+"}")

                    parsed_dict["download_info"] = download_file.get("downloadFile")
                    
                    parsed_dict["update_size"] = get_update_size(download_file.get("downloadFile"))

                    parsed_dict["version"] = get_version_number(download_file.get("downloadFile"))
            
                    parsed_dict["last_updated"] = get_last_updated(download_file.get("downloadFile"))
                    
                    parsed_dict["architecture"] = get_architecture(download_file.get("downloadFile"))

                
                    download_title = info_dict[info_dict.index("downloadTitle")-1:]
                    download_title = download_title[:download_title.index(r'",')+1]
                    download_title = json.loads("{"+download_title+"}")
                    
                    parsed_dict["title"] = download_title.get("downloadTitle")

                    if "kb" in download_title.get("downloadTitle").lower():

                        title = download_title.get("downloadTitle").lower()
                        if "kb" in title:
                            # get the kb number
                            kb_number = ""
                            kb_start_index = title.index("kb") + 2
                            for i in range(kb_start_index, len(title)):
                                if title[i].isdigit():
                                    kb_number += title[i]
                                else:
                                    break
                
                        parsed_dict["kb"] = kb_number

                    if not parsed_dict.get("kb") and get_kb_number(download_file.get("downloadFile")):
                        parsed_dict["kb"] = get_kb_number(download_file.get("downloadFile"))

                    #downloadDescription
                    download_description = info_dict[info_dict.index("downloadDescription")-1:]
                    download_description = download_description[:download_description.index(r'",')+1]
                    download_description = json.loads("{"+download_description+"}")
                    
                    parsed_dict["description"] = download_description.get("downloadDescription")

                    #,"operatingSystem"
                    operating_system = info_dict[info_dict.index("operatingSystem")-1:]
                    operating_system = operating_system[:operating_system.index(r'",')+1]
                    operating_system = json.loads("{"+operating_system+"}")
                    operating_system_value = operating_system["operatingSystem"]
                    parsed_dict["supported_products"] = operating_system_value

                    parsed_dict["language"] = language_name

                    parsed_dict["update_url"] = actual_download_link

                    update_details.append(parsed_dict)

        return update_details
    except Exception as e:
        print("Exception in get_microsoft_windows_product_update for url: {}, exception: {}".format(download_page_link, str(e)))
        return []
      
def get_patch_link(kb):
    try:
        # convert kb to str and lower
        kb = str(kb)
        kb = kb.lower().replace("kb", "")

        base_url = "https://support.microsoft.com/help/"
        url = base_url + kb
        user_agent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)"
        headers = {"User-Agent": user_agent}
        download_page_content = requests.get(url, headers=headers).content
        # Parse the HTML content
        soup = BeautifulSoup(download_page_content, 'html.parser')

        #get the actual link from the page
        #<link href="https://www.microsoft.com/en-us/download/details.aspx?id=105652" rel="canonical"/>
        canonical_link = soup.find("link", {"rel": "canonical"})
        if not canonical_link:
            return []
        
        actual_download_link = canonical_link.get("href")

        # get list of all links href
        all_anchor_tags = soup.find_all("a")
        if not all_anchor_tags:
            return []
        
        all_links = [
            anchor_tag.get("href") for anchor_tag in all_anchor_tags if anchor_tag.get("href") is not None
        ]

        actual_download_links = []
        for link in all_links:
            if "/download/details.aspx?" in link:
                actual_download_links.append(link)
        
        print("Found patch links using support url: {}".format(actual_download_links))
        
        return actual_download_links
    
    except Exception as e:
        print("Exception in get_patch_link for kb: {}, exception: {}".format(kb, str(e)))
        return []

def get_microsoft_download_center_update(remd_url,kb):
    try:
        patch_list = []
        update_details = get_microsoft_windows_product_update(remd_url)
        if update_details:
            for update in update_details:
                download_info = update["download_info"]
                # replace key url with download link
                # replace key name with file name
                for download_link_detail in download_info:
                    download_link_detail["download_link"] = download_link_detail["url"]
                    download_link_detail["file_name"] = download_link_detail["name"]

                download_urls = download_info
                title = update['title']
                description = update['description']
                supported_products = update['supported_products']
                language = update['language']
                version = update['version']
                update_size = update['update_size']
                last_updated = update['last_updated']
                update_url = update['update_url']
                patch_kb = update.get("kb")
                architecture = update.get("architecture")
                if not patch_kb:
                    patch_kb = kb

                patch_list.append({
                    "kb": patch_kb,
                    "title": title,
                    "kb_numbers": patch_kb,    
                    "version": version,
                    "last_updated": last_updated,
                    "classification" : "Product Update",
                    "languages": language,
                    "superseeds": "None",
                    "msrc_number": "None",
                    "msrc_severity": "None",
                    "products_applicable": supported_products,
                    "architecture": architecture,
                    "uninstallable" : "Yes",
                    "requires_connectivity": "No",
                    "requires_user_input": "No",
                    "requires_restart": "Yes",
                    "update_size": update_size,
                    "more_info" : update_url,
                    "description": description,
                    "support_url": "https://support.microsoft.com/help/" + patch_kb,
                    "download_urls": json.dumps(download_urls)
                })

            return patch_list
        
        else:
            print("No update found using microsoft download center link : {}".format(remd_url))
            return []
        
    except Exception as e:
        print("Exception in get_microsoft_download_center_update for url: {}, exception: {}".format(remd_url, str(e)))
        return []
 

if __name__ == '__main__':
    import sys
    import os

    if len(sys.argv) < 3:
        print("Usage: %s <search string> <file_path>" % os.path.basename(sys.argv[0]))
        sys.exit(1)

    search = sys.argv[1] # "4530684"
    file_path = sys.argv[2] # "update_details.json"

    # validate that search string is not empty
    if not search:
        print("Search string cannot be empty")
        sys.exit(1)

    if os.path.exists(file_path):
        os.remove(file_path)

    updates_json = {
        "updates": []
    }
    
    if not file_path:
        file_path = "update_details.json"

    updates = find_microsoft_catelogue_updates(search)
    if not updates:
        patch_links = get_patch_link(search)
        if not patch_links:
            print("No updates found for search string using microsoft download center: {}".format(search))
            sys.exit(1)

        update_list = []
        for patch_link in patch_links:
            updates_details = get_microsoft_download_center_update(patch_link,search)
            if updates_details:
                update_list.extend(updates_details)

        if update_list:
            updates_json["updates"] = update_list
    else:
        updates_json["updates"] = updates
            
    with open(file_path, 'w') as outfile:
         json.dump(updates_json, outfile)

