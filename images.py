import yaml

with open("list.txt") as stream:
    try:
        image_list = yaml.safe_load(stream)
        list = ""

        for image, information in image_list.items():
            image_info = information[0]

            image_name = image_info['image']
            image_tag = image_info['tag']

            image_name_tag = image_name + ":" + image_tag

            list += image_name_tag + " "

        print(list)

    except yaml.YAMLError as exc:
        print(exc)
