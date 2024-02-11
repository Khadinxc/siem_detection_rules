import tomllib
import os

#file = "alert_example.toml"
#with open(file,"rb") as toml:
#    alert = tomllib.load(toml)


for root, dirs, files in os.walk("elastic_rules"): 
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)

                present_fields = []
                missing_fields = []

                if alert['rule']['type'] == 'query': #query based alert
                    required_fields = ['author','description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query','threat']
                elif alert['rule']['type'] == 'eql': #event correlation alert
                    required_fields = ['author','description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language','threat']
                elif alert['rule']['type'] == 'threshold': #threshold based alert
                    required_fields = ['author','description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold','threat']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)


                if missing_fields:
                    print("The following fields do not exist in: " + file + ": " + str(missing_fields))
                else:
                    print("Validation Passed for: " + file)

                #print(required_fields)
                #print("\n")
                #print(present_fields)
                #print("\n")
                #print(missing_fields)