# project/recipes/views.py

#################
#### imports ####
#################
import os
import io
import requests
import datetime
from flask import render_template, Blueprint, request, redirect, url_for, flash, send_from_directory
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename
from werkzeug.datastructures import CombinedMultiDict
from project import db
from project.models import Report, User
import time


################
#### config ####
################

report_blueprint = Blueprint('report', __name__)
apikey = "1e485224849dd525aa4362d26b1bab3437974c18597157e0d8a316c62b0aebee"

##########################
#### helper functions ####
##########################

def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the %s field - %s" % (
                getattr(form, field).label.text,
                error
            ), 'info')


# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] == "txt"


def count_detection_mapping(engine):
    if (engine['detected']):
        return 1
    else:
        return 0

def add(x, y): return x + y 

################
#### routes ####
################

@report_blueprint.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    # Get the name of the uploaded file
    file = request.files['file']

    # Check if the file is one of the allowed types/extensions
    if file and allowed_file(file.filename):
        # Make the filename safe, remove unsupported chars
        filename = secure_filename(file.filename)

        fpath = os.path.join('uploads/', filename)
        file.save(fpath)
        fread = open(fpath, "r")
        for line in fread:

            try:
                # if db contains hash, and scan date is within 1 day, no need to update db
                report = Report.query.filter_by(hash_value=line.strip()).first()

                if (report and report.scan_date and (report.scan_date - datetime.datetime.now()).total_seconds() < 3600 * 24):
                    continue
                # else update the report
                # query each md5 hash
                params = {'apikey': apikey, 'resource': line.strip()}
                response = requests.post('https://www.virustotal.com/vtapi/v2/file/report', params = params)
                json_response = response.json()

                if (json_response['response_code'] == 1):
                    if json_response['scans']['Fortinet']['result'] == None:
                        Fortinet_detection = None
                    else:
                        Fortinet_detection = json_response['scans']['Fortinet']['result']
                    detected_engine_number = reduce(add, map(count_detection_mapping, json_response['scans'].values()), 0)

                    # parse time
                    scan_date = datetime.datetime.strptime(json_response['scan_date'], "%Y-%m-%d %H:%M:%S") 

                    if (report):
                        # update
                        report.Fortinet_detection = Fortinet_detection
                        report.detected_engine_number = detected_engine_number
                        report.scan_date = scan_date
                        report.filename = filename
                        report.user_email = current_user.email
                    else:
                        # insert
                        new_report = Report(params['resource'], 
                            Fortinet_detection,
                            detected_engine_number,
                            scan_date,
                            current_user.email,
                            filename,
                            True)
                        db.session.add(new_report)

                    db.session.commit()

                else:
                    # cannot find the scanned file
                    if (report):
                        report.Fortinet_detection = None
                        report.detected_engine_number = None
                        report.scan_date = None
                        report.filename = filename
                        report.user_email = current_user.email
                        report.scanned = False
                    else:
                        new_report = Report(params['resource'], 
                            None,
                            None,
                            None,
                            current_user.email,
                            filename,
                            False)
                        db.session.add(new_report)
                    
                    db.session.commit()

            except:
                print("Api call failed!")
                pass

            # Avoid reaching the query limit
            time.sleep(16)

        for r in Report.query.all():
            print(r.hash_value, r.user_email, r.filename, r.scanned, r.scan_date)

        # Redirect to new page displaying table of reports 
        return redirect(url_for('report.show_reports', filename=filename))



@report_blueprint.route('/reports/<filename>', methods=['GET'])
def show_reports(filename):
    # Obtain entries by [filename + user email]
    reports = Report.query.filter_by(filename=filename, user_email=current_user.email).all()
    return render_template('reports.html', reports=reports)



@report_blueprint.route('/reports', methods=['GET'])
def show_my_reports():
    # Obtain entries by [user email]
    reports = Report.query.filter_by(user_email=current_user.email).all()
    return render_template('reports.html', reports=reports)




@report_blueprint.route('/upload', methods=['GET', 'POST'])
def upload():
    return render_template('upload.html')
