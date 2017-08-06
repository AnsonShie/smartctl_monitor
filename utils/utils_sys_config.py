from configobj import ConfigObj
from utils_log import utils_log
sys_config_log = utils_log(name='utils_sys_config')


class utils_sys_config():
    """ Use ConfigObj to generate config file """
    def __init__(self, filename):
        self.filename = filename
        self.config = ConfigObj(self.filename, list_values=False)

    def write_to_file(self, file_name):
        self.config.write()
        orig_filename = self.config.filename
        self.config.filename = file_name
        self.config.write()
        self.config.filename = orig_filename

    def exist(self, section, keyword=None):
        if section not in self.config.keys():
            return False
        if keyword is None:
            # Only check section exists
            return True
        if keyword not in self.config[section].keys():
            return False
        return True

    def get_all_sections(self):
        return self.config.keys()

    def get_keyword_value_by_section(self, section):
        sys_config_log.logger.debug('section -> %s' % section)
        if section in self.config.keys():
            return self.config[section]
        else:
            sys_config_log.logger.error('section:%s does not exist' % (section))              
            return None

    def get_value_by_section_keyword(self, section, keyword, default=None):
        sys_config_log.logger.debug('section , keyword-> %s , %s' % (section, keyword))
        if section in self.config.keys():
            if keyword in self.config[section].keys():
                return self.config[section][keyword]
            else:
                sys_config_log.logger.error('keyword:%s of section:%s does not exist' % (keyword, section))
                return default
        else:
            sys_config_log.logger.error('section:%s does not exist' % (section))
            return default

    def add_section(self, section, keyword=None, value=None):
        # just to add section
        if keyword is None and value is None:
            self.config[section] = {}
            self.add_comment(section,'\n')
        # want to add section, keyword, and value
        else:
            # section name already exists, to add or modify keyword and value
            if section in self.config.keys():
                section1 = self.config[section]
                section1[keyword] = value
            # new section, new keywords, and new value
            else:
                self.config[section] = {}
                self.config[section][keyword] = value
                self.add_comment(section,'\n')
        self.config.write()
        return True

    def add_comment(self, section, comment):
        ''' the comment will be write up the section
            example:
            # test comments
            [section]
        '''
        self.config.comments[section]  = [comment]
        return True

    def del_section(self, section):
        try:
            del self.config[section]
        except KeyError:
            return True

        self.config.write()
        return True
    
    def add_keyword(self, keyword, value):
        self.config[keyword]=value
        self.config.write()
        return True        
        
    def get_keyword(self, keyword):
        if keyword in self.config.keys():
            return self.config[keyword]
        else:
            return None
            
    def del_keyword(self, keyword):
        if keyword in self.config.keys():   
            del self.config[keyword]
            self.config.write()
        return True   

    def edit_multi_level_section(self, section ,keyword, value):
        '''
        section value: ['section1','section2']
        example:
            [section1]
                [section2]
                    keyword=value
        '''
        if type(section) != list:
            print 'Input section type must be a list'
            return False
        tmp = 0
        for _section in section:
            try:
                tmp += 1
                if tmp == 1:
                    sectione1 = self.config[_section]
                else:
                    sectione1 = sectione1[_section]
            except:
                print 'Wrong section name %s' % _section
                return False
        sectione1[keyword] = value
        self.config.write()
        return True

    def write_script_type_file(self, fileName):
        try:
            #Write the file contents
            with open(fileName, 'w+') as file:
            #Loop through the file to change with new values in dict      
                for _key in self.get_all_sections():
                    line = _key + "=" + self.get_keyword(_key) + "\n"
                    file.write(line)
            return True
        except IOError as e:
            print "ERROR opening file " + fileName + ": " + e.strerror + "\n"  
            return False        

    def update_section_keyvalues(self, sec_name, keyvalues):
        """
        Update key value of a section
        """
        section = self.config[sec_name]
        for key in keyvalues:
            section[key] = keyvalues[key]

        self.config.write()
        return True


if __name__ == '__main__':
    network = utils_sys_config('/etc/sysconfig/network-scripts/ifcfg-eth0')
    print network.config      