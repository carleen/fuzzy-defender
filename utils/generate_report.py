from datetime import datetime
import os
import plotly.express as px
import pandas as pd

class Report:
    '''
    Class used to store the results of the simulation. Results
    will be stored within ./results/[date_and_time]
    
    
    --------------
    Attributes
    --------------
        name: str 
            Name of the simulation
        results: dict
            Results of the simulation
            
    --------------
    Methods
    --------------
        get_packet_rate(mu, stdev, min_munivorm, max_uniform)
    
    '''
    
    def __init__(self, name, results):
        
        self.name = name
        self.results = results
        
    def generate_plots(self, df, nodename, rpath):
        y_var_list = {'fuzzy_compromised_category': 'Fuzzy Compromised, Category', 
                      'fuzzy_compromised_value': 'Fuzzy Compromised, Pure Value'}
        
        for y_var in y_var_list:
            n = f'{y_var_list[y_var]}'
            
            fig1 = px.scatter(df, x='time', y=y_var, 
                              width=600, height=400, 
                              range_y=[-1.1, 1.1], 
                              range_x=[-0.5,100.5],
                      title=f'{n}',
                     labels={'fuzzy_compromised':'Compromised Rating',
                            'time': 'Simulation Time (s)'})
            try:
                fig1.to_image(os.path.join(rpath, f'{nodename}_{y_var}.png'))
            except ValueError:
                print('')
        
    
    def generate_report(self, results_dir):
        
        results = self.results
        
        # Get date and time
        dt_str = datetime.now().strftime("%Y-%m-%d_%H%m")
        dt_str = dt_str + f'_{self.name}'
        
        # Make directory
        os.mkdir(f'{results_dir}/{dt_str}')
        rpath = os.path.join(results_dir, dt_str)
        
        
        # Write the csv results to output
        for node_name in results:
            node_results = results[node_name]
            df = pd.DataFrame(node_results)
            df.to_csv(f'{rpath}/{node_name}.csv')
            
            # Generate the plots
            self.generate_plots(df, node_name, rpath)
        
        